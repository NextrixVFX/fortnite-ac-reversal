# 18 — ETW-TI and kernel hazards for spoofers

The specific kernel-side observability mechanisms that current-build EAC uses, and what each one constrains about spoofer / cheat kernel code.

This chapter is the "stuff that catches you besides the obvious callbacks."

---

## ETW-TI subscription

**The Microsoft-Windows-Threat-Intelligence ETW provider.** GUID: `{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}`.

A kernel ETW provider that emits events **from inside ntoskrnl** for specific suspicious operations. Normally subscribable only by Protected Process Light (PPL) subscribers — which EAC's driver qualifies as via its WHQL cross-signature.

### What it reports

Observable events when a process calls these from any thread:

| Operation | Event |
|-|-|
| `NtAllocateVirtualMemory` with exec protection | Virtual-allocation event |
| `NtProtectVirtualMemory` to change protection | **ProtectVirtualMemory event** |
| `NtMapViewOfSection` with exec | Mapped-view event |
| `NtReadVirtualMemory` cross-process | Cross-process-read event |
| `NtWriteVirtualMemory` cross-process | Cross-process-write event |
| `NtSetContextThread` cross-process | Context-set event |
| `NtQueueApcThread` cross-process | APC-queue event |
| `NtCreateThreadEx` cross-process | Remote-thread event |

Each event includes: **source process, target process, operation parameters, call stack.**

**EAC subscribes to this provider** (via the `EtwB` module from [15.3](15-driver-raw-offsets.md#section-153--the-46-module-manifest)) and relays suspicious events into its own telemetry.

---

## The spoofer problem — confirmed in `spoof.sys`

Direct evidence from a shipping HWID spoofer driver (`desire_market` build):

```
shm PATCH_PTE refused (EAC TI ProtectVm)
shm ALLOC refused (EAC TI AllocVm)
```

The spoofer uses a **shared-memory IPC** (`\BaseNamedObjects\EacEmuShm`) for user-mode cheat code to request kernel operations from the spoof driver. When the driver detects that EAC's TI subscription is active, it **refuses to perform PATCH_PTE or ALLOC on behalf of user-mode**, because those operations would generate TI events the EAC agent relays.

**The spoofer loses capability when EAC is watching.** This is the reason real commercial spoofers either:

1. Load **before** EAC's ETW subscription registers (race at boot).
2. Use operations that don't trigger TI events (physical-memory PTE writes, direct MMIO).
3. Accept the restriction and operate only in constrained ways.

---

## PatchGuard — what it prevents

**Kernel Patch Protection** periodically verifies a set of kernel structures and `.text` regions. Modifications → bugcheck `CRITICAL_STRUCTURE_CORRUPTION` (0x109).

Protected structures (non-exhaustive):

| Structure | What's protected |
|-|-|
| `ntoskrnl.exe` `.text` | Inline-hooking ntoskrnl functions is a bugcheck |
| `ntdll.dll` critical functions (user-mode but validated) | Some critical ntdll functions |
| `SSDT` (service descriptor table) | SSDT patching = bugcheck |
| `IDT` (interrupt descriptor table) | IDT hooking = bugcheck |
| `GDT` | GDT modifications = bugcheck |
| `KdpDebugRoutineSelect` | Kernel debugger table |
| Processor `MSRs` (specific set: `LSTAR`, etc.) | Syscall-handler MSR = bugcheck |
| `PsInvertedFunctionTable` | Exception-handling table |
| `KiServiceTable` | System call table |

**Implications for cheat / spoof drivers:**

- **No inline patching of ntoskrnl functions.** Use legal callbacks only.
- **No SSDT hooks.** Use kernel callbacks that forward to your handler.
- **No MSR rewriting of `LSTAR` to intercept syscalls.** The whole syscall-hooking approach is dead.

Legal alternatives:

- `PsSet*NotifyRoutine` for process/thread/image creation observation.
- `ObRegisterCallbacks` for handle-open interception.
- `CmRegisterCallback` for registry monitoring.
- `PsSetLegoNotifyRoutine` — stack-swap-time callback (rare use).
- `FltRegisterFilter` for filesystem filtering.
- `NdisFRegisterFilterDriver` for NDIS filtering.
- `MmGetSystemRoutineAddress` + device filter stacks for IOCTL interception.

**Everything EAC does is legal callback territory.** So anything you build has to coexist with EAC's callbacks without breaking the semantics EAC expects.

---

## HVCI / Code Integrity

**Hypervisor-Protected Code Integrity.** When enabled:

- Kernel pages marked executable must have a valid Microsoft-rooted signature.
- No kernel-mode `rwx` pages.
- No arbitrary executable allocation via `MmAllocateContiguousMemory` with `PAGE_EXECUTE_READWRITE`.
- Driver loads outside the Microsoft signing chain are rejected by the hypervisor, not just by user-mode code integrity.

**Implications:**

- **BYOVD on an HVCI-enabled system is harder.** The vulnerable driver loads, but any arbitrary kernel code you map via its primitive has to pass the hypervisor's integrity check too.
- `kdmapper` and similar tools fail on HVCI-enabled systems unless specifically designed for HVCI bypass (which involves finding a way to run attacker-chosen code in an existing legitimate executable region).
- EAC reports HVCI state as part of environmental fingerprint. Systems with HVCI off are a data point. **Turning HVCI off to run a cheat is itself a soft flag.**

---

## DMA Protection / Kernel DMA Protection

Controlled by:
- UEFI firmware's `DMA Protection` setting.
- Windows' `Kernel DMA Protection` policy.
- VT-d / AMD-Vi (IOMMU) state.

When enabled, **PCIe devices can only DMA into memory the OS has explicitly mapped for them.** Breaks external DMA cheats cleanly — the FPGA card can't just read anywhere; it has to go through IOMMU-mediated mappings.

**EAC reports DMA Protection state.** Systems with it off while a DMA cheat is active are a correlation data point. "This user has DMA Protection off" + "sometimes their aim is suspiciously perfect" = soft flag for behavioral correlation.

---

## Driver load auditing via WDAC

**Windows Defender Application Control** block list. Updated by Windows Update. EAC's `DRIVER_LIST` IOCTL ([02 — kernel driver](02-kernel-driver.md)) returns each loaded driver's WDAC-match state.

Known block-listed vulnerable drivers (publicly documented, representative subset):

```
RTCore64.sys       (MSI Afterburner — arbitrary MSR read/write)
GPC-U64.sys        (GPC — physical memory read/write)
ATSZIO64.sys       (ATSZ — arbitrary MSR + IO)
GDRV.sys           (Gigabyte — arbitrary I/O port)
DBUTIL_2_3.sys     (Dell — arbitrary MSR R/W)
WDLoadNTDriver.sys (WinRing0-related — arbitrary MSR)
AsIO.sys           (ASUS — arbitrary I/O port + MSR)
EneIo.sys          (ENE — physical memory read)
NalDrv.sys         (Intel Nahimic — arbitrary MSR)
LhaReb.sys         (various rebranded Realtek variants)
```

**EAC flags on WDAC-match regardless of whether the signature is still valid.** Microsoft revokes faster than Epic's rules.bin updates, so WDAC-match catches freshly-revoked drivers before rules.bin would.

---

## Boot chain observability

ACPI tables, UEFI variables, Secure Boot state, WBCL (Windows Boot Configuration Log) — all accessible to EAC's driver.

From `spoof.sys` strings:

```
AcpiRegistryPatched
AcpiTablesPatched
BootCurrent
BootNext
BootOptionSupport
BootOrder
SecureBoot
WBCLColdboot
WBCLDrtmColdboot
WindowsBootSession
```

These are the fields the spoofer has to maintain consistent spoofed values across. Specifically:

- **ACPI tables**: DSDT, SSDT, FACP, APIC, DMAR, IVRS, HPET, WAET, MCFG, BGRT, TPM2, TCPA, SLIC, MSDM, SRAT, SLIT, BERT, HEST, ERST, FPDT, NHLT, XSDT, RSDT, OEM1-4, DBG2, DBGP, WSMT, IORT, LPIT.
- **UEFI boot vars**: Order + current + next.
- **Secure Boot state**: enabled/disabled — EAC reports this.
- **WBCL** (Windows Boot Configuration Log): the event log of boot-phase decisions. Useful forensic artifact.

**A durable spoofer has to patch all of these before EAC's `env_worker` reads them.** Current-build EAC re-reads ACPI OEM ID + table IDs on the ~30s env_worker tick.

---

## Why cheats pre-load before EAC

Timing matters. If your driver loads **before** EAC's:

- Your filter drivers register above the storage/NDIS/display stack.
- Your ObCallbacks register before EAC's (altitude competition — you can pick an altitude above EAC's).
- You read baseline HWID / ETW state before EAC does.
- EAC's self-integrity check sees a kernel with "extra" callbacks that weren't there when previous session's baseline was captured.

Current-build EAC catches late-loaded drivers via the "load time" classifier in the `DRIVER_LIST` IOCTL ([02](02-kernel-driver.md)) — drivers that load outside the boot-time window are flagged. **Which is a double-edge** — pre-boot is better for driver-load hygiene, worse because EAC's initial baseline captures your spoofer's effects as "the norm" and you can't change them later without drift detection firing.

---

## Signal: the ETW providers EAC subscribes to

Reconstructed from static analysis + behavior:

- `Microsoft-Windows-Threat-Intelligence` (TI).
- `Microsoft-Windows-Kernel-Process`.
- `Microsoft-Windows-Kernel-Registry` (complementing CmRegisterCallback).
- `Microsoft-Windows-DNS-Client`.
- `Microsoft-Windows-Winsock-AFD`.
- `Microsoft-Windows-Kernel-Audit-API-Calls`.

These are in addition to the custom callbacks (process/thread/image/handle). ETW gives EAC a second data channel into the same events, resistant to the "unregister the callback" cheat approach.

---

## Spoofer build requirements summary

For a spoofer to work reliably against current EAC:

1. **Load pre-boot** (UEFI bootkit or very-early boot driver) OR **load before EAC's service starts** AND register before EAC's TI subscription fires.
2. **Patch SMBIOS at the physical table + ntoskrnl cache.**
3. **Hook storage stack** (disk.sys, storahci, stornvme, storport) for serial-number IOCTLs.
4. **Hook NDIS** for permanent-MAC IOCTL.
5. **Hook display stack** or inject EDID into registry early.
6. **Patch ACPI OEM IDs** consistently.
7. **Don't trigger TI events** when operating — so no `NtProtectVirtualMemory` to change page protections after boot, no `NtAllocateVirtualMemory` for executable memory. Use boot-time allocations, no runtime patching.
8. **Maintain SMBIOS history consistency** — same values across sessions.
9. **Keep driver image hash out of WDAC block list** — rotate BYOVD or self-sign with clean cert.
10. **Match load time to "boot bulk" window.**

This is a lot. Which is why "spoofer development" is a full-time job for the few teams that actually ship reliable ones, and why commercial spoofers cost what they do.

---

**Next:** [Analysis — three emulator architectures compared](analysis/00-index.md)
