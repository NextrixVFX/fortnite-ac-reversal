# B — HWID checks, kernel spoofers, the spoof surface

Covers: every HWID source EAC reads (from [A.2](10-cleaner-ban-traces.md#a2--live-queried-machine-identifiers-the-hwid--fingerprint-set)), the mechanism by which each source is actually read on Windows, and how kernel-level spoofers alter each source.

**"Spoofer"** here means a kernel driver (or kernel-only patch set) that intercepts reads of the HWID fields and returns altered values, aiming to make the hashed fingerprint different from the banned hash.

A map of the attack surface. Useful for both the defender (plug the holes) and the attacker (know what needs patching).

---

## B.1 — SMBIOS

### What it is

SMBIOS (System Management BIOS) is a set of structured tables stored in physical memory by the BIOS/UEFI at boot. Tables are indexed by type:

- Type 0: BIOS
- Type 1: System
- Type 2: Baseboard
- Type 3: Chassis
- ...

Each table is a fixed-layout structure with string references.

### How Windows exposes SMBIOS

```
(a) user-mode via WMI:
      Win32_BIOS                → BIOS info (type 0)
      Win32_ComputerSystemProduct → system info (type 1)
      Win32_BaseBoard           → baseboard (type 2)
      Win32_SystemEnclosure     → chassis (type 3)
    WMI provider ultimately IOCTLs into \Driver\WMIxWDM

(b) user-mode via GetSystemFirmwareTable:
      GetSystemFirmwareTable('RSMB', 0, buffer, size)
    Returns raw SMBIOS table blob. What current EAC uses directly.

(c) kernel-mode via NtQuerySystemInformation:
      NtQuerySystemInformation(SystemFirmwareTableInformation,
                               request, requestSize, &returned)
    With request.Action = SystemFirmwareTable_Get and
         request.ProviderSignature = 'RSMB'
    This is EAC's driver path.
```

### How spoofers alter it

A spoofer that wants to change what EAC sees has to patch **all three paths**. Patching only WMI leaves `GetSystemFirmwareTable` showing real values. Patching only user-mode `GetSystemFirmwareTable` leaves the driver's `NtQuerySystemInformation` call returning real values.

**The real work is at the kernel path**, because the user-mode paths ultimately funnel through kernel-side firmware-table retrieval.

Kernel-side work involves intercepting `ExpQuerySystemFirmwareTable` (the undocumented internal function `NtQuerySystemInformation` ends up calling for `'RSMB'`). Two approaches:

1. **Hook `ExpQuerySystemFirmwareTable` directly.** Painful because PatchGuard protects ntoskrnl `.text`.
2. **Patch the SMBIOS table itself in physical memory** — more durable. The physical SMBIOS table lives at a specific physical address recorded in the UEFI configuration tables; map it via `MmMapIoSpace` and overwrite the string fields.

### The caching problem

Once you alter the table in memory, you have to keep it altered. Windows caches the SMBIOS table at boot and some code paths read from cache rather than re-reading physical memory. A proper spoofer alters the cached copy inside ntoskrnl's data section too.

Find the cache by xrefs from `ExpQuerySystemFirmwareTable` in a kernel disassembly of your Windows build. Apply the alteration there. Now every query is consistent.

### The drift-detector problem

EAC's `env_worker` runs environment-consistency checks every 30s. It re-reads SMBIOS and compares against session-init snapshot. If a lazy spoofer only altered the first read's result but didn't patch durably, env_worker catches drift.

A proper spoofer must either:

- **(a)** Patch durably so every read returns the same spoofed values, OR
- **(b)** Also hook the env_worker's read path specifically (requires hooking the user-mode agent — more fragile).

### Which fields to alter

Most-to-least weight (if trying to beat an HWID ban):

| Table | Field | Priority |
|-|-|-|
| 1 | system UUID (16 bytes, strong identifier) | **must** |
| 1 | system serial number (string) | **must** |
| 2 | baseboard serial (string) | **must** |
| 2 | baseboard manufacturer | should |
| 2 | baseboard product name | should |
| 1 | system manufacturer | should |
| 1 | system product name | should |
| 3 | chassis serial | should |
| 0 | BIOS vendor | optional |
| 0 | BIOS version | optional |

### Anomaly-list hazard

Rules.bin section `0x70` (SMBIOS anomaly list) has block entries for values EAC's backend considers "known fake":

- `"To be filled by O.E.M."`
- `"Default string"`
- `"System Manufacturer"`
- Specific leaked public OEM strings known to be reused by spoofers

Section `0x71` (firmware version block list) blocks known fake BIOS version strings.

A spoofer has to generate **plausible-looking fresh values**, not filler.

---

## B.2 — Disk serials, volume serials, SMART

### Physical disk serial

Read via:

```c
DeviceIoControl(hDisk, IOCTL_STORAGE_QUERY_PROPERTY,
                StorageDeviceProperty, ...);
```

Returns `STORAGE_DEVICE_DESCRIPTOR` with `VendorIdOffset`, `ProductIdOffset`, `SerialNumberOffset`. The serial is what EAC cares about most.

The IOCTL is handled by `\Driver\disk` → `\Driver\storport` → the SCSI/NVMe miniport. A spoofer either hooks `disk.sys`'s dispatcher (more PatchGuard-flaggable) or — more durably — registers a filter driver above `disk.sys`. The filter intercepts the IOCTL return path and rewrites `SerialNumber` offset content.

### NVMe-specific identifiers

```c
DeviceIoControl(hDisk, IOCTL_STORAGE_PROTOCOL_COMMAND, ...);
```

NVMe `identify-controller` returns:

- `EUI64` (8 bytes)
- `NGUID` (16 bytes)

Hardware-rooted. Spoof via the same filter approach, different command.

### Per-volume serial (NTFS)

```c
GetVolumeInformation() → volume serial (32-bit)
```

Stored in the NTFS boot sector. Spoofing requires:

- Altering the boot sector directly (can conflict with Windows' boot-sector protection on current builds — Secure Boot + BitLocker detection).
- Or hooking the user-mode API chain (more fragile, reversible).

### SMART data

Not an HWID field strictly, but `GetSMARTData` can reveal power-on hours and reallocated sector counts. Not EAC-relevant; mentioned for completeness.

### Spoofer considerations

1. **Disk serials are read at various times by various code paths.** The spoofer has to filter every path or EAC's driver will see the real serial via its own IOCTL.
2. **Filter driver above `disk.sys` is the clean approach.** Hooking `disk.sys`'s dispatcher directly works but is more PatchGuard-flaggable.
3. **Current-build EAC compares disk serial via both the user-mode IOCTL path and a WMI query.** A spoofer that only hooks one shows drift.

---

## B.3 — MAC addresses

### Current MAC vs permanent MAC

Two different values the system tracks:

| | Current MAC | Permanent MAC |
|-|-|-|
| What | The active MAC on the adapter | The one the NIC hardware was manufactured with |
| Read via | `OID_802_3_CURRENT_ADDRESS` | `OID_802_3_PERMANENT_ADDRESS` |
| Settable via | Registry `NetworkAddress` under adapter's class key, adapter's advanced properties UI | **Cannot** be changed via registry — it's in the NIC's EEPROM |
| Used for | Actual network traffic | — |

**EAC reads the PERMANENT MAC, not the current one.** Registry-level MAC changer tools do nothing against EAC fingerprinting.

### Registry path for current MAC (for reference)

```
HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\<index>
Value name: NetworkAddress
```

### Spoofing permanent MAC

Three approaches:

1. **Filter driver above the specific miniport.** Rewrites responses to `OID_802_3_PERMANENT_ADDRESS`. Cleanest option.
2. **Hook the NDIS IM (intermediate module) layer.** Rewrite responses before they bubble up.
3. **Some NICs have EEPROM update tools** that change the burned-in MAC. Nontrivial, requires the correct firmware tools, varies per NIC vendor.

### MAC prefix hazard

If your fake permanent MAC uses a prefix that doesn't match any registered OUI, EAC flags. The anomaly list in rules.bin (`0x70` is used for MAC prefix checks too in newer builds) blocks known fake prefixes.

A spoofer generates MACs with real-OUI prefixes.

---

## B.4 — CPU identifiers

CPUID is a CPU instruction. The kernel can intercept it via VT-x / AMD-V by causing vmexits on CPUID — but that's a **hypervisor-level** spoofer, not a driver one. On bare metal, CPUID returns what the silicon returns. **You cannot spoof CPUID via a kernel driver on a non-virtualized system.**

### What EAC reads

```
CPUID 1 (signature, feature flags)
CPUID 0x80000002-4 (brand string, 48 chars)
CPUID 4 (cache topology)
CPUID 0xB / 0x1F (topology)
CPUID 0x16 (frequency)
CPUID 3 (processor serial, deprecated — but still probed)
```

### Spoofer options

| Option | Trade-off |
|-|-|
| Run under a hypervisor that intercepts CPUID and returns altered values | EAC detects hypervisors (see [08 — protection stack](08-protection-stack.md)); triggers anti-VM flags unless the hypervisor is stealthy |
| Hook the user-mode agent's CPUID wrapper to return altered values | Fragile; EAC's agent has multiple CPUID call sites, some VMP'd. Miss one → drift. |
| Hook ntoskrnl's CPUID helpers (`KeGetCpuId` or similar) | Same risk; PatchGuard-adjacent |

**Bottom line:** CPUID spoofing on bare metal requires hypervisor-level control. Most "spoofers" do not spoof CPUID — they rely on CPU fingerprint being a low-weight contributor to the ban hash.

---

## B.5 — GPU and DXGI adapter

### GPU LUID

The LUID is a 64-bit identifier assigned by Windows to the GPU. Stable per boot per adapter, regenerates on driver reinstall or on major Windows updates. Not as stable as SMBIOS UUID but still a fingerprint contributor.

**Spoofing:**

- Hook `IDXGIAdapter::GetDesc1` at user-mode inside the agent.
- Or more durably at `dxgi.dll` system-wide. **But** EAC's integrity timer hashes `dxgi.dll`'s `.text`, so inline-patching in memory is caught.
- Need an API-hook approach that doesn't modify `dxgi`'s `.text` — either EAT/IAT hooking (has its own detection surface via EAC's export-pointer check) or `PAGE_EXECUTE_WRITECOPY` CoW tricks.

### Vendor-specific UUIDs

`NVAPI`, `ADLX`, `IGCL` queries. Hooking these in the vendor driver's user-mode component is possible but requires per-vendor work.

### PCI subsystem/vendor/device IDs

Read from `HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_*\DEV_*`. Spoofable at the registry layer **but** the driver itself still knows the real IDs via PCI config-space reads. EAC's driver can enumerate PCI config space directly via Hal / pciport. So pure-registry spoofing is caught by driver-side cross-check.

---

## B.6 — Monitor EDID

The monitor's EDID (Extended Display Identification Data) blob is 128 or 256 bytes read from the display via DDC/CI over I2C. Windows caches it in the registry:

```
HKLM\SYSTEM\CurrentControlSet\Enum\DISPLAY\*\*\Device Parameters\EDID
```

Contains manufacturer ID, product code, serial number, mfg date. Weak fingerprint but contributes.

**Spoofing:** Write the altered EDID into the registry key. Also need to intercept any code path that reads EDID directly from the display (bypassing the registry cache). The display driver does this on hotplug — a filter driver on the display stack can intercept.

---

## B.7 — TPM endorsement key

Newer EAC builds (post-2024) query the TPM endorsement key (EK) via TBS (TPM Base Services) APIs: `Tbsi_Get_TCG_Log`, `Tbsi_Create` / `Tbsi_Submit_Command` with a `TPM2_ReadPublic` for the EK handle.

### Why TPM EK is hard to spoof

- The EK is a per-TPM-chip RSA or ECC key provisioned at manufacture.
- Its public portion is stable until the TPM is cleared.
- Hash of the EK public is **one of the hardest fingerprints to spoof on bare metal.**

### Spoofing TPM EK

| Approach | Trade-off |
|-|-|
| Virtualized TPM (fTPM / dTPM emulation in a hypervisor) | EAC detects hypervisors → triggers anti-VM flags |
| Clearing the physical TPM (changes EK) | **One-shot** — destroys your BitLocker keys among other things |
| Hook TBS at user-mode or driver level to return altered EK public | Fragile; EAC's env_worker re-reads |

**Most current spoofers either:**

- Skip TPM entirely and accept the TPM-hash contribution to their ban hash (hoping the backend weighs it with enough slack), or
- Require you to clear the TPM before use.

There is **no general-purpose durable TPM EK spoofer** that is robust against re-read drift.

---

## B.8 — Windows identity fields

### Machine GUID

```
HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
```

A per-install random GUID generated at Windows install. **Spoofable via registry write.**

### ProductId, DigitalProductId, SQMClient MachineId

All registry writes. Spoofable trivially **but** EAC's env_worker re-reads at the 30s cadence. So long as the spoofer altered the registry before session start AND values remain altered (nothing's regenerating them), fine. Windows itself doesn't regenerate these except at reinstall/sysprep.

### User SID

Tied to the local user account. New user account → new SID. Not spoofable at the SID itself, but the fingerprint reads the SID of the running user token. **"Switch user accounts" is the non-spoof workaround.**

---

## B.9 — Full spoofer architecture

A complete HWID spoofer that beats EAC's current fingerprint surface needs all of the following capabilities. Omitting any one of them creates a detectable gap.

### 1. Kernel-mode presence

Achieved through one of:

**(a) A signed driver.** Unusual — signed driver attack surface is small and usually gets revoked once detected.

**(b) BYOVD (Bring Your Own Vulnerable Driver).** Load a known-vulnerable signed driver and use its arbitrary read/write primitive to map and execute the spoofer's unsigned code. Current popular vulnerable drivers rotate as Microsoft revokes signatures via the WDAC block list. **EAC's `DRIVER_LIST` IOCTL now returns WDAC block-list match state**, so vulnerable drivers with revoked signatures are flagged on load.

**(c) Manual mapping** via `kdmapper` or similar, using a BYOVD primitive. The mapped driver has no backing `\SystemRoot` file but still gets a VAD entry and still registers whatever callbacks it registers. EAC's `CALLBACK_DUMP` catches new callbacks and compares the owning-driver hash against its own whitelist. A manual-mapped driver has no on-disk hash match to anything — itself a flag.

### 2. SMBIOS patching

Both physical memory + ntoskrnl cached copy. See B.1.

### 3. `disk.sys` / `storport` filter

For `IOCTL_STORAGE_QUERY_PROPERTY`, `IOCTL_STORAGE_PROTOCOL_COMMAND`. See B.2.

### 4. NDIS filter or miniport filter

For `OID_802_3_PERMANENT_ADDRESS`. See B.3.

### 5. Display stack filter OR EDID registry overwrite + hotplug interception

See B.6.

### 6. Registry writes

For machine GUID, ProductId, DigitalProductId, SQMClient MachineId. See B.8.

### 7. TPM strategy

Either clear the TPM, run under a hypervisor, or accept the TPM-hash contribution. See B.7.

### 8. GPU

DXGI adapter desc hook (best-effort, not durable), vendor driver API hook (per-vendor work). See B.5.

### 9. Anti-detection hardening

- **Don't register competing kernel callbacks** that EAC would see in `CALLBACK_DUMP` (manual-map and use direct syscall tables for hooking rather than callbacks).
- **Don't leave the driver in loaded-driver lists** where EAC's `DRIVER_LIST` would return it. Manual mapping + removing the `PsLoadedModuleList` entry is standard.
- **Don't be visible in the VAD scan for the game process** (non-issue for a kernel driver — game process doesn't contain the driver's memory).
- **Re-patch on 30s cadence** to defeat EAC's env_worker drift detection — but ideally with a durable patch that doesn't need re-patching.

---

## The arms race, summarized

Three detection axes a spoofer has to stay ahead of:

| If the spoofer… | …it gets caught by |
|-|-|
| Patches once at load but doesn't sustain | `env_worker` drift detection |
| Patches durably but registers detectable kernel callbacks | `CALLBACK_DUMP` |
| Does neither but uses a vulnerable driver with a revoked signature | `DRIVER_LIST` + WDAC state |

The operational problem for spoofers is staying ahead of all three. Commercial spoofers rotate BYOVDs on a cadence matching Microsoft's revocation pace; open-source spoofers tend to lag and get caught faster.

---

**Next:** [C — Cheat detection surface](12-cheat-detection.md)
