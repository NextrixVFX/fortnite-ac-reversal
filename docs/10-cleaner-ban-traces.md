# A — Cleaner & ban traces

The surface involved in **"this machine was flagged / banned"** and **"this hardware is the same hardware that was banned"**. Two overlapping concerns:

| | Concern | Lives in |
|-|-|-|
| **(a)** | On-DISK traces correlating "your machine" to "this account's ban" via log files, caches, registry, event logs. | Filesystem + registry + system event logs |
| **(b)** | Live-queried machine identifiers correlating "your hardware" to "banned hardware" via hardware fingerprinting. | Hardware + firmware + OS install state |

**Both matter.** Cleaning only (a) when (b) is the real binding gets you nowhere. Cleaning only (b) when (a) still shows "this machine has run and been reported by EAC N times" also gets you nowhere.

---

## A.1 — On-disk traces EAC and the system leave

### EAC-specific trace locations

```
C:\ProgramData\EasyAntiCheat\                       — persistent config,
                                                      boot cookies, cached
                                                      session metadata
C:\ProgramData\EasyAntiCheat_EOS\                   — same for EOS variant
C:\ProgramData\Epic\EasyAntiCheat\Logs\             — run logs with session IDs
%LOCALAPPDATA%\EasyAntiCheat\                       — per-user caches
%LOCALAPPDATA%\EasyAntiCheat_EOS\
C:\ProgramData\Epic\EpicGamesLauncher\Data\Logs\   — launcher logs, which
                                                     include EAC service
                                                     start/stop events
                                                     and process spawn
                                                     records
C:\Program Files (x86)\EasyAntiCheat\              — system install dir;
                                                     contains the shared
                                                     driver copy + setup
                                                     log
C:\Windows\System32\LogFiles\EasyAntiCheat\        — present on some
                                                     builds; driver-side
                                                     crash dumps + status
```

### Fortnite-specific

```
%LOCALAPPDATA%\FortniteGame\Saved\Logs\             — client-side game logs
                                                      with session IDs that
                                                      Epic's backend can
                                                      correlate
%LOCALAPPDATA%\FortniteGame\Saved\Config\           — user-ID artifacts +
                                                      session continuation
                                                      data
%LOCALAPPDATA%\FortniteGame\Saved\Crashes\          — crash reports (which
                                                      include hardware
                                                      fingerprints)
%LOCALAPPDATA%\FortniteGame\Saved\WebCache*\        — web cache
%LOCALAPPDATA%\EpicGamesLauncher\Saved\
  DeviceIdCache*                                     — device id cache, per-
                                                      user epic device
                                                      fingerprint
```

### Registry locations EAC writes or reads through

```
HKLM\SYSTEM\CurrentControlSet\Services\EasyAntiCheat
HKLM\SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS
HKLM\SOFTWARE\EasyAntiCheat
HKLM\SOFTWARE\WOW6432Node\EasyAntiCheat
HKCU\Software\EasyAntiCheat                         — per-user cache
HKLM\SYSTEM\CurrentControlSet\Services\EasyAntiCheat\Enum
                                                     — PnP enum entry
HKLM\SYSTEM\Setup\LastUserShellFolders               — occasionally touched
                                                     during install/update
```

### Windows forensic artifacts that outlive EAC's own cleanup

#### Prefetch

```
C:\Windows\Prefetch\
  EASYANTICHEAT.EXE-*.pf
  EASYANTICHEAT_LAUNCHER.EXE-*.pf
  FORTNITECLIENT-WIN64-SHIPPING_EAC.EXE-*.pf
  FORTNITECLIENT-WIN64-SHIPPING_EAC_EOS.EXE-*.pf
  FORTNITELAUNCHER.EXE-*.pf
```

Records volume paths, DLLs loaded, run count, first/last run time. **Forensic timeline gold.**

#### Event Logs (`.evtx`)

```
C:\Windows\System32\winevt\Logs\System.evtx
  — service start/stop events for EasyAntiCheat
  — driver load events (Microsoft-Windows-Services)
  — Code Integrity events if the driver had any load drama

C:\Windows\System32\winevt\Logs\Application.evtx
  — any crashes from the game or EAC

C:\Windows\System32\winevt\Logs\
  Microsoft-Windows-Kernel-PnP%4Device*.evtx
  — device enum events for the EAC driver device

C:\Windows\System32\winevt\Logs\
  Microsoft-Windows-TaskScheduler%4Operational.evtx
  — if EAC used a scheduled task
```

#### SRUM database

```
C:\Windows\System32\sru\SRUDB.dat
```

Per-executable network bytes transferred and runtime stats. Shows "this machine ran `EasyAntiCheat.exe` and `FortniteClient-*` and transferred N bytes to Epic endpoints." Aggregated hourly.

#### BAM (Background Activity Moderator)

```
HKLM\SYSTEM\CurrentControlSet\Services\bam\UserSettings\<SID>
```

Per-SID list of executables run and their last run time. Includes EAC and Fortnite binaries.

#### MUICache

```
HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\
  Shell\MuiCache
```

Binary full paths and `FriendlyAppName` values for executables that ran under this user.

#### Shimcache (AppCompat)

```
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
```

List of executable paths + last-modified times observed. Kept across reboots, flushed to registry only at reboot.

#### Amcache.hve

```
C:\Windows\appcompat\Programs\Amcache.hve
```

**The heaviest forensic witness.** Detailed record of every executable run, with SHA1 hashes of the binaries themselves. Amcache shows not just that a binary ran but the specific version.

#### Jump Lists

```
%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\
```

Per-application recent-files lists.

#### NTFS USN Journal

```
$Extend\$UsnJrnl:$J
```

Filesystem change journal. Records creation/modification of EAC files, log files, etc. Huge, but chunks can survive long enough to matter.

#### Paging / hibernation

```
C:\pagefile.sys
C:\hiberfil.sys
C:\swapfile.sys
```

Paged-out memory from any process. Can contain literal cleartext of pipe frames, session IDs, HWID tokens that EAC computed.

#### Volume Shadow Copies

```
vssadmin list shadows
```

Point-in-time snapshots. Any snapshot made while EAC was installed contains the full forensic record above.

#### WER (Windows Error Reporting) queue

```
C:\ProgramData\Microsoft\Windows\WER\
```

Cached crash dumps that haven't been uploaded yet. If Fortnite or EAC ever crashed, a minidump may be here with a full memory snapshot of the crashing process.

### Epic launcher caches

```
C:\ProgramData\Epic\EpicGamesLauncher\
%LOCALAPPDATA%\EpicGamesLauncher\
```

Contain your Epic account ID, device ID cache, sessions, auth tokens. **Tied to your account even if you log out.**

---

## A.2 — Live-queried machine identifiers (the HWID / fingerprint set)

These are the fields EAC reads and reports to the backend as your hardware fingerprint. The backend stores a hash of some combination per session. An HWID ban blacklists that hash.

### SMBIOS

Read via one of:

- `NtQuerySystemInformation(SystemFirmwareTableInformation, 'RSMB')` — current EAC path
- `GetSystemFirmwareTable('RSMB', 0, buffer, size)` — user-mode equivalent
- WMI: `Win32_BIOS` / `Win32_BaseBoard` / `Win32_ComputerSystem` / `Win32_SystemEnclosure`

Fields:

| Table | Field | Weight |
|-|-|-|
| 0 (BIOS) | vendor | low |
| 0 | version | low |
| 0 | release date | low |
| 1 (System) | manufacturer | moderate |
| 1 | product name | moderate |
| 1 | version | low |
| 1 | serial number | **high** |
| 1 | **UUID** | **high (strong identifier)** |
| 2 (Baseboard) | manufacturer | moderate |
| 2 | product name | moderate |
| 2 | **serial number** | **high** |
| 3 (Chassis) | manufacturer | low |
| 3 | serial | moderate |

### Disk

```
per-physical-drive serial number via
  IOCTL_STORAGE_QUERY_PROPERTY with StorageDeviceProperty
per-physical-drive model + firmware via same
NVMe identify-controller via IOCTL_STORAGE_PROTOCOL_COMMAND
  (NVMe EUI64 + NGUID)
per-volume serial number via GetVolumeInformation
  (NTFS boot sector field — lower entropy than physical serial
   but still recorded)
```

### Network

```
per-adapter PERMANENT MAC via NDIS IOCTL
  (NOT the "current" MAC — asks for the burned-in one)
per-adapter description + hardware ID from registry under
  HKLM\SYSTEM\CurrentControlSet\Enum\PCI\...
per-adapter IPv6 global prefix (less stable, still captured)
```

### CPU

```
CPUID leaf 1 EAX/EBX/ECX/EDX (signature, feature flags)
CPUID brand string (leaves 0x80000002..0x80000004)
CPUID leaf 0x16 processor frequency (or computed TSC rate fallback)
CPUID leaf 4 cache topology
CPUID leaf 0x1F / 0xB extended topology — NUMA + core layout
microcode revision via RDMSR 0x8B (kernel side)
processor serial number via CPUID leaf 3 if available (deprecated on
  modern CPUs but EAC still probes)
```

### GPU

```
adapter LUID + description via DXGI IDXGIAdapter::GetDesc1
PCI subsystem/vendor/device IDs via setupapi
  HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_*\DEV_*
nvidia-specific device UUID via NVAPI (if nvidia driver present)
intel-specific device UUID via IGCL / IGDUMD queries
amd-specific via ADLX / AMDVLK queries
```

### Audio / input

```
audio endpoint device IDs via IMMDeviceEnumerator
mouse/keyboard HID paths via SetupDiGetClassDevs
```

### Display

```
monitor EDID via setupapi registry under
  HKLM\SYSTEM\CurrentControlSet\Enum\DISPLAY\*\*\Device Parameters\EDID
```

Contains manufacturer ID, product code, serial number, mfg date.

### TPM (newer builds, when present)

```
TPM endorsement key public — hash strongly stable per-TPM
  (survives Windows reinstall; only replaced if TPM is cleared or
   motherboard swapped)
TPM manufacturer ID + version via TBS APIs
```

### Windows / OS identity

```
HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductId
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DigitalProductId
  (4 bytes of installation ID, basically unique per install)
HKLM\SOFTWARE\Microsoft\SQMClient\MachineId
current user SID from the user token
Windows build number + revision
```

### Firmware tables beyond SMBIOS

```
ACPI tables via NtQuerySystemInformation(SystemFirmwareTableInformation, 'ACPI')
  — ACPI OEM ID + OEM table ID
  — MSDM table on OEM machines (contains OEM Windows product key)
PCI config space for each device via IoGetDeviceProperty
  — driver-side; EAC's driver can enumerate all PCI devices and hash
```

### Boot / firmware state

```
UEFI firmware vendor + version via GetFirmwareEnvironmentVariable
Secure Boot state
HVCI / VBS state
Windows Memory Integrity (code integrity for drivers) state
DMA Guard / Kernel DMA Protection state
```

### Weight summary

Each field is hashed into contributions to the backend fingerprint. Weighting (reconstructed from observed behavior — exact weights are Epic's secret):

- **Heaviest:** motherboard UUID, TPM EK, disk serials, permanent MAC, machine GUID
- **Moderate:** baseboard serial, chassis serial, system product/manufacturer, CPU brand + topology, GPU LUID
- **Lightest:** monitor EDID, audio endpoints, BIOS vendor/version strings

An HWID ban blacklists a combination hash across some subset. The exact combination is Epic's secret. Probability of getting past an HWID ban by changing one field is low; the ban hash is tolerant to single-field drift up to a point.

---

## A.3 — Comprehensive cleaner operation inventory

The full surface you'd need to touch for a comprehensive clean. This is an **inventory**, not an operational guide. Operational steps are left to the operator. Reinstalling Windows is the "nuclear" option and cleaner than any delete script because it regenerates the Windows identity fields along with the forensic artifacts.

| # | Step |
|-|-|
| 1 | Uninstall EAC and Fortnite via Epic launcher (regular path) |
| 2 | Uninstall system-wide EAC via its uninstaller |
| 3 | Delete `ProgramData` and `LocalAppData` directories listed in A.1 |
| 4 | Delete Epic Games Launcher install directory |
| 5 | Delete Fortnite's saved data |
| 6 | Clear registry keys listed in A.1 |
| 7 | Clear prefetch (files, not the directory) |
| 8 | Clear event logs (requires admin; **creates its own event log entry about the clearing**, which is itself forensically relevant) |
| 9 | Clear BAM via the SID subkey |
| 10 | Clear MUICache |
| 11 | Clear Shimcache — requires a reboot after registry wipe because Shimcache is read at boot and flushed at shutdown |
| 12 | Delete `Amcache.hve` — locked at runtime; needs offline boot or scheduled deletion |
| 13 | Wipe NTFS `$UsnJrnl` |
| 14 | Delete `pagefile.sys`, `hiberfil.sys`, `swapfile.sys` (disable paging, reboot, re-enable to regenerate empty) |
| 15 | Delete all VSS snapshots: `vssadmin delete shadows /all /quiet` |
| 16 | Delete WER queued dumps |
| 17 | Delete jump lists |
| 18 | Clear Windows Search index: `net stop wsearch` then delete `C:\ProgramData\Microsoft\Search\Data\Applications\Windows\` |
| 19 | Clear recycle bin |
| 20 | Clear browser caches and history for any browser used to access Epic accounts |
| 21 | **Recognize that none of this touches the HWID binding — see A.4** |

---

## A.4 — Why cleaning alone doesn't beat HWID bans

**The critical point.** EAC's and Epic's backend don't need your on-disk forensic artifacts to re-recognize banned hardware. At next session start:

1. Agent collects the live-queried identifiers in A.2.
2. Hashes them.
3. Sends the hash.
4. Backend compares against the ban list.
5. Match → ban.

### Cleaning helps

- Prevent a **future** investigation from tying a new identifier to the old ban through log correlation on your disk.
- Make a disputed appeal less open-and-shut.
- Reset local caches that EAC uses for drift detection (future sessions start fresh).

### Cleaning does not

- Unban your hardware.
- Prevent the HWID hash on next launch from matching the ban list.
- Affect Epic's server-side records of your ban at all.

### The one operation that does beat an HWID ban on the same hardware

Spoof the inputs that go into the HWID hash. That's [B — HWID spoofing](11-hwid-spoofing.md).

---

**Next:** [B — HWID spoofing surface](11-hwid-spoofing.md)
