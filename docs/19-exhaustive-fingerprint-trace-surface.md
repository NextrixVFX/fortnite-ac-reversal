# 19 — Exhaustive fingerprint / trace / check surface (the catch-all)

Everything EAC can observe about your machine, every trace it leaves, every identifier that goes into HWID binding, every CPU/firmware/kernel/network check — in one catalog. If something isn't in the other docs, it's in here. Cross-referenced where appropriate.

**Read as reference, not linear.** Use Ctrl+F.

---

## Part 1 — Hardware identifiers (every field, every subsystem)

### 1.1 — CPU identifiers

**Via CPUID (user-mode accessible, no kernel required):**

| Leaf | Field |
|-|-|
| `0x00` | Vendor string (GenuineIntel / AuthenticAMD / HygonGenuine / CentaurHauls / etc.) + max leaf |
| `0x01` | Family / Model / Stepping (EAX), brand / APIC ID / core count (EBX), feature flags (ECX + EDX) |
| `0x02` | Cache + TLB descriptors (Intel legacy) |
| `0x03` | **Processor Serial Number** — deprecated on P4+, still probed by EAC per [15.5](15-driver-raw-offsets.md#section-155--hwid-formatter-0x914b2--0x92e78) |
| `0x04` | Cache topology (deterministic cache parameters) |
| `0x05` | MONITOR/MWAIT info |
| `0x06` | Thermal and power management features |
| `0x07` | Structured extended feature flags (sub-leaves 0, 1, 2) |
| `0x09` | Direct Cache Access (DCA) |
| `0x0A` | Architectural Performance Monitoring |
| `0x0B` | Extended topology (SMT, core, package) |
| `0x0D` | XSAVE features + state components |
| `0x0F` | Resource Director Technology (RDT) monitoring |
| `0x10` | RDT allocation |
| `0x11` | — |
| `0x12` | SGX capabilities (sub-leaves 0, 1, 2+) |
| `0x14` | Processor Trace enumeration |
| `0x15` | **TSC and core crystal clock info** — `CoreCrystalFreq = TSCFreq * EBX / EAX` |
| `0x16` | Processor frequency info (Base, Max, Bus) — must be nonzero on real hardware |
| `0x17` | SoC Vendor attributes |
| `0x18` | Virtual Address Translation parameters |
| `0x19` | Key Locker info (Intel KL) |
| `0x1A` | Hybrid information (P-core vs E-core on 12th gen Intel+) |
| `0x1B` | PCONFIG target identification |
| `0x1C` | Last Branch Records (LBR) |
| `0x1D` / `0x1E` | AMX (Advanced Matrix Extensions) tile / TMUL info |
| `0x1F` | V2 extended topology |
| `0x20` | HRESET features |
| `0x21` | Reserved / AMX-reserved |
| `0x40000000` | **Hypervisor-present leaf** — brand string if HV present |
| `0x40000001..0x4000000A` | Hyper-V TLFS leaves if Hyper-V is HV |
| `0x80000000` | Max extended leaf |
| `0x80000001` | Extended features (LAHF, SVM, LM, etc.) |
| `0x80000002..0x80000004` | Brand string ("Intel(R) Core(TM)...") — 48 chars |
| `0x80000005` | L1 cache + TLB |
| `0x80000006` | L2 + L3 cache |
| `0x80000007` | APM features |
| `0x80000008` | Virtual + physical address sizes |
| `0x8000000A` | SVM (AMD virtualization) features |
| `0x80000019` | TLB characteristics |
| `0x8000001D` | Cache properties |
| `0x8000001E` | Extended APIC + topology |
| `0x8000001F` | SEV + SME features (AMD confidential compute) |
| `0x80000020` | PQoS |
| `0x80000021` | Extended feature identification (AMD) |
| `0x8FFFFFFF` | Centaur-private / reserved |

**Via MSR reads (kernel-mode only):**

| MSR | Address | What |
|-|-|-|
| `IA32_PLATFORM_ID` | `0x17` | Platform ID for microcode binding |
| `IA32_APIC_BASE` | `0x1B` | APIC base + enable + BSP flag |
| `IA32_FEATURE_CONTROL` | `0x3A` | VMX enable, SGX enable, etc. |
| `IA32_TSC_ADJUST` | `0x3B` | TSC adjustment value (per-core) |
| `IA32_SPEC_CTRL` | `0x48` | Speculation control (IBRS/STIBP/SSBD) |
| `IA32_PRED_CMD` | `0x49` | Branch prediction barrier |
| `IA32_BIOS_UPDT_TRIG` | `0x79` | Microcode update |
| `IA32_BIOS_SIGN_ID` / `IA32_UCODE_REV` | `0x8B` | **Microcode revision** |
| `IA32_PLATFORM_INFO` | `0xCE` | Platform-specific info (max non-turbo ratio etc.) |
| `IA32_PERFEVTSEL0..7` | `0x186+` | Performance counter config |
| `IA32_PERFCTR0..7` | `0xC1+` | Performance counter values |
| `IA32_MTRRCAP` | `0xFE` | MTRR capabilities |
| `IA32_SYSENTER_CS/ESP/EIP` | `0x174..0x176` | SYSENTER state |
| `IA32_DEBUGCTL` | `0x1D9` | Debug control (LBR, BTS) |
| `IA32_MTRR_PHYSBASE0..N` / `PHYSMASK0..N` | `0x200+` | Memory Type Range Registers |
| `IA32_PAT` | `0x277` | Page Attribute Table |
| `IA32_EFER` | `0xC0000080` | Extended Feature Enable Register (LMA, SCE, NXE, SVME) |
| `IA32_STAR/LSTAR/CSTAR/FMASK` | `0xC0000081..84` | Syscall state (PatchGuard protects these) |
| `IA32_FS_BASE` / `GS_BASE` / `KERNEL_GS_BASE` | `0xC0000100..102` | Thread-local base registers |

### 1.2 — SMBIOS (all tables)

Per [15.5](15-driver-raw-offsets.md#section-155--hwid-formatter-0x914b2--0x92e78), accessed via `NtQuerySystemInformation(SystemFirmwareTableInformation, 'RSMB')`, WMI `Win32_*`, or `GetSystemFirmwareTable`. **Includes history** — driver remembers values across sessions.

| Type | Table | Key fields |
|-|-|-|
| 0 | BIOS | Vendor, Version, Release Date, BIOS Characteristics, Embedded Controller firmware version |
| 1 | System | Manufacturer, Product, Version, **Serial Number**, **UUID**, WakeUp Type, SKU, Family |
| 2 | Baseboard | Manufacturer, Product, Version, **Serial Number**, Asset Tag, Features, Chassis Handle |
| 3 | Chassis | Manufacturer, Type, Version, **Serial Number**, Asset Tag, Boot-up State, Power Supply State, Thermal State, Security Status, OEM Info |
| 4 | Processor (per CPU) | Socket, Manufacturer, Version, Voltage, External Clock, Max Speed, Current Speed, Status, **Processor ID**, Serial Number, Asset Tag, Part Number |
| 7 | Cache (per cache) | Socket Designation, Configuration, Max Size, Installed Size, Speed, Error Correction Type, System Cache Type |
| 9 | System Slots | Slot Designation, Type, Data Bus Width, Current Usage, Length, Slot ID, Characteristics |
| 11 | OEM Strings | Free-form OEM strings (often used for Windows OEM activation keys, vendor info) |
| 12 | System Configuration Options | Configuration strings |
| 13 | BIOS Language Info | Installable languages, current language |
| 16 | Physical Memory Array | Location, Use, Error Correction, Max Capacity, Number of Devices |
| 17 | Memory Device (per DIMM) | Total Width, Data Width, Size, Form Factor, Locator, Bank Locator, Type, Type Detail, Speed, Manufacturer, **Serial Number**, Asset Tag, Part Number, Rank, Configured Memory Speed, Minimum/Maximum Voltage |
| 19 | Memory Array Mapped Address | Starting Address, Ending Address, Memory Array Handle |
| 20 | Memory Device Mapped Address | Starting Address, Ending Address, Memory Device Handle |
| 32 | System Boot Info | Boot Status |
| 38 | IPMI Device Info | IPMI version, I2C target address, etc. |
| 39 | Power Supply (per supply) | Manufacturer, Serial Number, Asset Tag, Model, Revision |
| 41 | Onboard Devices Extended Info | Reference Designation, Device Type, Device Status, Type Instance, Segment Group Number, Bus Number, Device/Function Number |

### 1.3 — Storage devices

Beyond physical disk serial:

| Field | Access path |
|-|-|
| Physical disk serial, model, firmware | `IOCTL_STORAGE_QUERY_PROPERTY` → `StorageDeviceProperty` |
| Disk adapter info | `IOCTL_STORAGE_QUERY_PROPERTY` → `StorageAdapterProperty` |
| NVMe EUI64 + NGUID | NVMe Identify Controller via `IOCTL_STORAGE_PROTOCOL_COMMAND` |
| NVMe namespace ID | per-namespace identifier |
| NVMe controller ID (CNTLID) | Identify Controller response |
| NVMe subsystem NQN | NVMe Subsystem Qualified Name |
| SATA controller device ID | PCI config space of the storage controller |
| SATA signature | PM registers of each port |
| **SCSI LUN** | per [15.5](15-driver-raw-offsets.md) — formatter string `":lun=%llx"` |
| **MBR disk signature** | Dword at offset `0x1B8` of MBR — formatter `"MBR:%08x"` |
| **Partition index** | formatter `"Part:%u"` |
| **Optical drive index** | formatter `"CD:%u"` |
| Volume serial (NTFS) | 32-bit, boot sector |
| Volume serial (FAT) | 32-bit, VBR |
| $MFT entry 0 creation time | Volume creation timestamp, forensically stable |
| EFI System Partition GUID | GPT, stable per install |
| GPT Disk GUID | GPT header, per-disk unique |
| GPT Partition GUIDs | per-partition, stable |
| S.M.A.R.T attribute values | Power-on hours, reallocated sector count, etc. — not identifying alone but contributes |
| BitLocker volume ID (if encrypted) | per-volume FVE ID |
| Shadow Copy history | Per-volume VSS snapshot list |
| SRL (Storage Replica Log) presence | Server SKUs |

### 1.4 — Network (deep)

Beyond MAC addresses:

| Field | Source |
|-|-|
| Permanent MAC per adapter | `OID_802_3_PERMANENT_ADDRESS` via NDIS |
| Current MAC | `OID_802_3_CURRENT_ADDRESS` |
| Interface GUID | `HKLM\SYSTEM\CurrentControlSet\Control\Network\{4d36e972-...}\<guid>` |
| Driver DeviceInstanceID | `PCI\VEN_XXXX&DEV_XXXX&SUBSYS_XXXX&REV_XX\<instance>` |
| IPv6 interface identifier (SLAAC) | EUI-64 derived from MAC |
| IPv6 temporary addresses | RFC 4941, randomized |
| IPv6 link-local | `fe80::...` |
| Configured DNS servers | per-interface |
| DHCP client identifier | `DhcpIdentifier` registry value |
| WAN public IP | `nltest`, external HTTPS probe, or routing table |
| ARP cache entries | gateway MAC + neighbor list |
| **Wi-Fi SSID history** | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\` + `Signatures\Unmanaged\` |
| Wi-Fi BSSID (AP MAC) during session | wlanapi |
| **Bluetooth adapter address** | `HKLM\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\LocalServices` |
| Bluetooth paired device list | Same registry hive |
| **TLS JA3/JA4 fingerprint** of your client hello | EAC backend observes passively |
| TCP MSS, window size, timestamp option | OS fingerprint passive |
| IPv6 temporary-address rotation cadence | Correlation signal |
| Default route metrics + DNS cache patterns | Route table + dnsapi |
| Teredo / 6to4 state | If enabled, identifier in prefix |
| NDI (Networking Diagnostic Information) telemetry provider | ETW |
| WinHTTP proxy config | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings` |

### 1.5 — Display / graphics

| Field | Source |
|-|-|
| GPU adapter LUID | `IDXGIAdapter::GetDesc1` |
| GPU device description | Same |
| GPU vendor/device/subsystem/revision | PCI config space + `HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_*\DEV_*` |
| GPU VRAM size | Dedicated/shared video memory |
| WDDM version | `DXGI_GPU_PREFERENCE` |
| D3D feature level | Highest supported FL |
| NVIDIA GPU UUID | NVAPI `NvAPI_GPU_GetGPUInfo` or NVML `nvmlDeviceGetUUID` |
| NVIDIA PCI bus address | NVAPI |
| NVIDIA driver version | registry + NVAPI |
| NVIDIA Resizable BAR state | NVAPI |
| AMD GPU UUID | ADLX |
| Intel GPU UUID | IGCL |
| **Monitor EDID** (per monitor) | `HKLM\SYSTEM\CurrentControlSet\Enum\DISPLAY\*\*\Device Parameters\EDID` |
| EDID parsed fields | Manufacturer ID (PNP), Product code, Serial number, Mfg year/week, Preferred timing (DTD) |
| EDID extensions (CEA) | Audio formats, HDMI vendor-specific data block |
| Monitor name (via DDC/CI) | Query via DisplayConfigGetDeviceInfo |
| Monitor serial (from EDID) | DTD `#SN` tag |
| DisplayPort DPCD | AUX channel, OUI, device IDs |
| Active refresh rate + resolution | `EnumDisplaySettings` |
| Primary monitor identifier | `MONITOR_DEFAULTTOPRIMARY` |
| DWM composition state | `DwmIsCompositionEnabled` |

### 1.6 — USB / HID

Each connected device:

| Field | Source |
|-|-|
| USB device VID/PID/revision | PnP enum path |
| USB device serial number | USB string descriptor (if device provides one) |
| USB class/subclass/protocol | USB device descriptor |
| Container ID GUID | `HKLM\SYSTEM\CurrentControlSet\Enum\USB\*\*\Properties\{...}\0008` |
| Hub location path | PnP device instance path `USB\ROOT_HUB...` |
| **USB connection history** | `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` (USB mass storage), `USB\VID_*` (all) — forensic |
| HID top-level collection usage | HID report descriptor |
| HID report descriptor hash | For mouse/keyboard, identifies the device generation |
| Mouse polling rate (measured) | Input event timing |
| Keyboard layout ID | `HKEY_CURRENT_USER\Keyboard Layout` |
| Last connected timestamp per USB device | `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\*\Properties\{...}\0064` |

### 1.7 — Audio

| Field | Source |
|-|-|
| **Audio endpoint device IDs** (GUIDs) | `IMMDeviceEnumerator::EnumAudioEndpoints` |
| Primary playback endpoint | `GetDefaultAudioEndpoint(eRender, eConsole)` |
| Primary capture endpoint | `GetDefaultAudioEndpoint(eCapture, eConsole)` |
| Endpoint friendly names | device property store |
| Audio device sub-types | HDAUDIO vs USB vs Bluetooth |
| Sample rate / bit depth per endpoint | Mix format |
| Audio session GUIDs | per-app audio sessions |
| Audio engine shared mode exclusive status | AudioClient properties |
| Audio volume (per-app history) | `HKCU\Software\Microsoft\Internet Explorer\LowRegistry\Audio\PolicyConfig\PropertyStore` |

### 1.8 — Firmware / boot (deep)

| Field | Source |
|-|-|
| UEFI firmware vendor + version | `GetFirmwareEnvironmentVariable` |
| **Secure Boot state** | `BOOT_OPTIONS` + UEFI var `SecureBoot` |
| **Secure Boot DB / DBX / KEK / PK hashes** | UEFI vars, TPM-measured |
| Boot Configuration Data (BCD) GUIDs | `BCDEdit` output / `HKLM\BCD00000000` |
| BootCurrent / BootNext / BootOrder | UEFI vars |
| HVCI state | `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity` |
| VBS state | `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\EnableVirtualizationBasedSecurity` |
| DMA Protection (Kernel DMA) | Policy registry + ACPI DMAR table |
| IOMMU (VT-d / AMD-Vi) state | ACPI DMAR/IVRS table parsing |
| **WBCL** (Windows Boot Configuration Log) | `C:\Windows\Logs\MeasuredBoot\` — per-boot `.log` files with TPM-measured values |
| **WBCL Coldboot / DRTM Coldboot** events | As called out in [spoof.sys](analysis/01-desire-market-emulator.md) |
| **ACPI tables** (all) | `NtQuerySystemInformation(SystemFirmwareTableInformation, 'ACPI')` — DSDT, SSDT, FACP, APIC, DMAR, IVRS, HPET, WAET, MCFG, BGRT, TPM2, TCPA, SLIC, MSDM, SRAT, SLIT, BERT, HEST, ERST, FPDT, NHLT, XSDT, RSDT, OEM1-4, DBG2, DBGP, WSMT, IORT, LPIT |
| ACPI OEM ID + OEM Table ID | All tables have these — fingerprint of firmware |
| MSDM table contents | OEM Windows product key — not read by EAC typically but fingerprint source |
| Firmware mode (UEFI vs Legacy) | `GetFirmwareType` API |
| CSM (Compatibility Support Module) state | UEFI setting |
| TPM version (1.2 / 2.0) | TBS `Tbsi_GetDeviceInfo` |
| TPM manufacturer | TBS |
| TPM firmware version | TBS |
| **TPM Endorsement Key public** | TPM2_ReadPublic for EK handle |
| EK certificate | `TpmRetrieveEkCertificate` |
| TPM PCR values (per bank: SHA1, SHA256) | TPM2_PCR_Read |
| AIK (Attestation Identity Key) | Per-platform, OS-provisioned |
| TPM quote on PCRs | **Bound to EAC session via `EacQuoteKey`** |
| Windows DRTM (Secure Launch) state | Boot measurement events |

### 1.9 — Memory (RAM) fingerprint

| Field | Source |
|-|-|
| RAM module serials (per-DIMM) | SMBIOS type 17 |
| RAM manufacturer per-DIMM | SMBIOS type 17 |
| RAM part number per-DIMM | SMBIOS type 17 |
| Total installed RAM | `GlobalMemoryStatusEx` |
| **SPD (Serial Presence Detect) raw data** | SMBus (via `\Driver\smbctrl` / `\Driver\i801` — called out in [spoof.sys](analysis/01-desire-market-emulator.md)) — **`RamSpdSerials`** field |
| XMP profile ID (if enabled) | SPD extension blocks |
| Memory channel configuration | SMBIOS |
| ECC vs non-ECC | SMBIOS + chipset |

### 1.10 — Power / battery

| Field | Source |
|-|-|
| Battery serial number | `GetSystemPowerStatus` + ACPI `_BIX` |
| Battery manufacturer, chemistry, design capacity | ACPI `_BIX` |
| AC adapter type | `SYSTEM_POWER_STATUS` |
| UPS presence + model | If present |
| CPU thermal design power (TDP) | SMBIOS |

### 1.11 — Camera / webcam

| Field | Source |
|-|-|
| Attached camera device paths | DirectShow / `IMFActivate` |
| Camera serial numbers (per-device) | USB descriptor if applicable |

### 1.12 — PCI device enumeration

For every PCI device, EAC's `Devi` module ([15.3](15-driver-raw-offsets.md#section-153--the-46-module-manifest)) can extract:

| Field |
|-|
| Vendor ID / Device ID |
| Subsystem Vendor ID / Subsystem Device ID |
| Revision ID |
| Class / Subclass / Programming Interface |
| Capabilities list (walk linked list at config offset 0x34) |
| PCIe capability — Device/Link/Slot caps + control + status |
| Message Signaled Interrupts (MSI/MSI-X) state |
| Bus/Device/Function (BDF) — topology |
| Secondary bus number (bridges) |
| BAR values (Base Address Registers) |
| Interrupt line + pin |
| **PnP instance path** — e.g. `PCI\VEN_10DE&DEV_2504&SUBSYS_41501458&REV_A1\4&3C24B4C&0&0008` — covered under `PciInstancesSpoofed` in [spoof.sys](analysis/01-desire-market-emulator.md) |
| ACS (Access Control Services) capability |
| ATS (Address Translation Services) state |
| PRI (Page Request Interface) state |

### 1.13 — SMBus / sensors

Called out by name in [spoof.sys](analysis/01-desire-market-emulator.md) (`\Driver\SMBUS`, `\Driver\amd_smbus`, `\Driver\i801`, `\Driver\smbctrl`):

| What |
|-|
| SPD data for RAM (via SMBus addresses 0x50-0x57) |
| Super I/O controller IDs |
| Thermal sensor readings |
| Fan controller state |

---

## Part 2 — OS-level identifiers

### 2.1 — Windows install identity

| Field | Registry path / Source |
|-|-|
| `MachineGuid` | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` |
| `MachineSid` | `HKLM\SECURITY\SAM\Domains\Account\F` (requires SYSTEM) |
| `SqmClient\MachineId` | `HKLM\SOFTWARE\Microsoft\SQMClient\MachineId` |
| Windows **InstallDate** | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\InstallDate` (unix timestamp) |
| Windows **InstallTime** | Same key, `InstallTime` (FILETIME) |
| `ProductId` | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductId` |
| `DigitalProductId` | Same key — 4 bytes of install ID, per-install unique |
| `DigitalProductId4` | Newer schema |
| **Edition ID** | Same key, `EditionID` |
| **Product Name** | Same key, `ProductName` |
| **CurrentBuild** / `CurrentBuildNumber` / `UBR` | Same key — exact build + Update Build Revision |
| `DisplayVersion` / `ReleaseId` | Same key — "22H2" / "24H2" etc. |
| `RegisteredOwner` / `RegisteredOrganization` | Same key |
| Upgrade history | `HKLM\SYSTEM\Setup\Source OS *` subkeys if upgraded |
| Windows Update HistoryID | `HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc\PendingActionsCache` + `WindowsUpdate` client ID |
| Windows **Device ID** (via Microsoft Account) | `HKLM\SYSTEM\CurrentControlSet\Services\DsSvc` |
| Windows **DeviceCensus ID** | `HKLM\SOFTWARE\Microsoft\SQMClient\Reliability\ADFR` |

### 2.2 — Azure AD / Microsoft Account state

| Field | Source |
|-|-|
| Azure AD join state | `dsregcmd /status` output + `HKLM\SYSTEM\CurrentControlSet\Control\CloudDomainJoin` |
| Azure AD tenant ID | Same |
| Device ID | Same |
| Microsoft Account linked user | `HKLM\SOFTWARE\Microsoft\IdentityCRL\UserExtendedProperties\<email>` |
| MSA user CID | Same hive |
| Credential Guard state | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LsaCfgFlags` |

### 2.3 — User identity

| Field | Source |
|-|-|
| User SID | Current token |
| User profile path | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>\ProfileImagePath` |
| User account creation time | `net user <username>` or profile folder timestamp |
| User RID | Last chunk of SID |
| Primary group ID | Token |
| Logon session LUID | Token (changes per logon) |

### 2.4 — System state fingerprints

| Field | Source |
|-|-|
| Boot time (system uptime) | `GetTickCount64` |
| Timezone | `GetTimeZoneInformation` |
| Locale | `GetUserDefaultLCID` / `GetSystemDefaultLCID` |
| Country code | `GetUserGeoID` |
| Keyboard layout | `HKEY_CURRENT_USER\Keyboard Layout\Preload` |
| **Hostname** | `GetComputerNameEx` |
| DNS domain | `GetComputerNameEx(ComputerNameDnsDomain)` |
| NetBIOS name | `GetComputerNameNetBIOS` |
| Installed .NET versions | `HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\` |
| Installed VC++ Redist versions | `HKLM\SOFTWARE\Microsoft\VisualStudio\<ver>\VC\Runtimes\` |
| Installed KB numbers | `wmic qfe` / `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages` |
| **Installed Windows features** | `DISM /Get-Features` state |
| **Installed drivers** | `HKLM\SYSTEM\DriverDatabase\DriverPackages` — every driver ever installed |

### 2.5 — Service state

| Field |
|-|
| Running services list |
| Service start types |
| Service dependency graph |
| EAC service state (`EasyAntiCheat` / `EasyAntiCheat_EOS`) |
| Driver services currently active |

---

## Part 3 — Kernel-side observable surfaces

### 3.1 — ETW providers EAC may subscribe to

Beyond `Microsoft-Windows-Threat-Intelligence` ([18](18-etw-ti-and-kernel-hazards.md)):

| Provider | What it reveals |
|-|-|
| `Microsoft-Windows-Kernel-Process` | Process creation, thread creation, image load (cross-check against callbacks) |
| `Microsoft-Windows-Kernel-Registry` | Every registry read/write (cross-check against CmRegisterCallback) |
| `Microsoft-Windows-Kernel-File` | File operations |
| `Microsoft-Windows-Kernel-Memory` | Memory allocation events |
| `Microsoft-Windows-Kernel-Audit-API-Calls` | Audited sensitive API calls |
| `Microsoft-Windows-DNS-Client` | DNS queries made by any process |
| `Microsoft-Windows-Winsock-AFD` | Socket operations |
| `Microsoft-Windows-TCPIP` | TCP connection events |
| `Microsoft-Windows-Kernel-PnP` | Device plug/unplug |
| `Microsoft-Windows-USB-USBHUB3` | USB hub events |
| `Microsoft-Windows-Kernel-Image` | Image load events |
| `Microsoft-Windows-Services` | Service state changes |

### 3.2 — Kernel structures walked

| Structure | Access |
|-|-|
| `PsLoadedModuleList` | Walk list head to enumerate loaded drivers |
| Driver object trees | `IoDriverObjectType` namespace walk |
| Device object trees | per `IoDeviceObjectType` |
| `KeServiceDescriptorTable` | SSDT (PatchGuard protected, read-only observation) |
| `KiServiceTable` entries | For syscall-function fingerprinting |
| `MmPfnDatabase` | Page Frame Number database — can detect swapped physical pages |
| `PsActiveProcessHead` | Active process list head |
| EPROCESS `VadRoot` offset | Per-process VAD tree root ([02](02-kernel-driver.md)) |
| EPROCESS `Token` | Current token |
| EPROCESS `ImageFileName` | Short process name |
| EPROCESS `Peb` | Process Environment Block pointer |
| ETHREAD `Tcb.ApcState` | APC queue state — detects APC injection |
| ETHREAD `StartAddress` | Thread entry point |
| ETHREAD `Win32StartAddress` | User-mode thread start |
| `KUSER_SHARED_DATA` | Shared kernel/user page — version info, time, feature flags |
| `KPRCB` (Processor Control Block) | Per-CPU state including context switches |

### 3.3 — Handle table walks

| What |
|-|
| System-wide handle table enumeration (`NtQuerySystemInformation(SystemHandleInformation)`) |
| Handles to protected process (filter by target PID) |
| Handles to protected threads |
| Handles to protected sections |
| Granted access masks per handle |
| Opener PID per handle |

### 3.4 — Object namespace

| Objects created / observed by EAC |
|-|
| `\Device\EasyAntiCheat_<random>` |
| `\DosDevices\EasyAntiCheat` |
| `\BaseNamedObjects\Global\EasyAntiCheat_EOSEventDriver` |
| `\BaseNamedObjects\Global\EasyAntiCheat_EOSEventGame` |
| `\BaseNamedObjects\Global\EasyAntiCheat_EOSEventModule` |
| Named pipes (`\Device\NamedPipe\EasyAntiCheat_<guid>`) |
| Shared memory sections (`\BaseNamedObjects\...`) |

### 3.5 — Memory introspection (`ViMm` module)

| What |
|-|
| VAD tree enumeration per process |
| EPROCESS field consistency (e.g., `UniqueProcessId` matches handle table) |
| Page protection state per VAD |
| Executable memory not backed by a module (shellcode detection) |
| Transient-executable VADs (R/W → R/X flip detection) |
| Entropy analysis of executable regions |
| PE header integrity for loaded modules |
| Section hash drift from baseline |

### 3.6 — Register / context inspection

| What | Access |
|-|-|
| Debug registers Dr0..Dr7 (per thread) | `GetThreadContext` |
| Control registers CR0..CR4 | kernel-side, MSR-adjacent |
| XCR0 (extended control) | `XGETBV` |
| FS/GS base | `rdfsbase` / `rdgsbase` or MSR |
| MXCSR state | FPU state save |
| Flags register | per-syscall analysis |

---

## Part 4 — Network / passive fingerprints

### 4.1 — TLS fingerprinting

| Field | What it fingerprints |
|-|-|
| JA3 hash | ClientHello cipher suite order + extensions |
| JA4 hash | Extended JA3 including ALPN, sig algs |
| ClientHello extension order | TLS stack identifier |
| Supported groups (curves) order | Browser/OS stack |
| Signature algorithms list | Same |
| ALPN values | App-level protocol signal |

### 4.2 — TCP/IP stack fingerprinting

| Field | Source |
|-|-|
| TCP initial window size | OS stack fingerprint |
| TCP MSS | OS stack |
| TCP timestamp option | CPU clock derived |
| TCP options order | OS stack |
| IPv4 TTL initial value | 64 / 128 / 255 — OS signal |
| IPv6 Hop Limit initial | Same |
| TCP SACK behavior | OS stack |

### 4.3 — DNS behavior

| Field |
|-|
| Configured DNS servers |
| DNS over HTTPS / DNS over TLS state |
| Local DNS cache patterns |
| mDNS / LLMNR presence |

---

## Part 5 — Timing fingerprints

Per [07 Fortnite integrity](07-fortnite-integrity.md) + [15.5 HWID](15-driver-raw-offsets.md#section-155--hwid-formatter-0x914b2--0x92e78), EAC uses rdtsc timing extensively:

| Timing probe | What it detects |
|-|-|
| rdtsc delta across CPUID | CPUID vmexit cost under hypervisor |
| rdtsc delta across MSR read | MSR vmexit cost under hypervisor |
| rdtsc delta across port I/O | I/O vmexit cost |
| rdtsc delta across interrupt | Interrupt latency fingerprint |
| QPC (QueryPerformanceCounter) vs rdtsc | TSC consistency across cores |
| HPET vs TSC | Timer source consistency |
| APIC timer vs rdtsc | Timer cross-check |
| TSC desync between cores | CPU-level fingerprint |
| Context switch latency | Scheduler fingerprint |
| IPI (Inter-Processor Interrupt) latency | SMP fingerprint |

---

## Part 6 — On-disk forensic artifacts (complete catalog)

Extends [10 cleaner & ban traces](10-cleaner-ban-traces.md):

### 6.1 — Already covered in [10]

- Prefetch files (`C:\Windows\Prefetch\`)
- Event logs (`winevt\Logs\*.evtx`)
- SRUM (`SRUDB.dat`)
- BAM registry
- MUICache registry
- Shimcache (AppCompat)
- Amcache.hve
- Jump lists
- USN Journal
- Pagefile / Hiberfil / Swapfile
- VSS snapshots
- WER queue
- Browser caches

### 6.2 — Additional forensic artifacts

| Artifact | Path |
|-|-|
| **ActivityHistory / Timeline** | `%LOCALAPPDATA%\ConnectedDevicesPlatform\<id>\ActivitiesCache.db` — SQLite database of app activity |
| **Diagnostic data** | `C:\ProgramData\Microsoft\Diagnosis\` — ETW traces, telemetry events |
| **Telemetry ETL files** | `C:\ProgramData\Microsoft\Windows\WER\Temp\` + `Diagnosis\ETLLogs\` |
| **Shellbags** | `HKCU\Software\Microsoft\Windows\Shell\Bags` + `BagMRU` — folder view history |
| **Thumbcache** | `%LOCALAPPDATA%\Microsoft\Windows\Explorer\thumbcache_*.db` |
| **IconCache** | `%LOCALAPPDATA%\IconCache.db` |
| **LNK files in Recent** | `%APPDATA%\Microsoft\Windows\Recent\` — per-file shortcuts |
| **RecentDocs** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\` |
| **UserAssist** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\` — ROT13-encoded app launch counts |
| **TypedPaths** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths\` |
| **OpenSaveMRU / LastVisitedPidlMRU** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\` |
| **RDP connection history** | `HKCU\Software\Microsoft\Terminal Server Client\` |
| **Windows Push Notification** | `%LOCALAPPDATA%\Microsoft\Windows\Notifications\wpndatabase.db` |
| **Credential Manager** | `%APPDATA%\Microsoft\Credentials\` + `%LOCALAPPDATA%\Microsoft\Credentials\` |
| **DPAPI master keys** | `%APPDATA%\Microsoft\Protect\<SID>\` |
| **LSA secrets** | Registry, requires SYSTEM: `HKLM\SECURITY\Policy\Secrets` |
| **Scheduled Tasks** | `C:\Windows\System32\Tasks\` |
| **Services registry** | `HKLM\SYSTEM\CurrentControlSet\Services\` — every service ever installed |
| **DriverStore** | `C:\Windows\System32\DriverStore\FileRepository\` — every driver INF ever installed |
| **Windows.old** (if upgrade) | Prior OS install remnants |
| **Volume Shadow Copies** | `System Volume Information\` (per-volume) |
| **Index.dat / WebCache** (IE legacy, still touched) | `%LOCALAPPDATA%\Microsoft\Windows\WebCache\` |
| **Browser CacheV2** (Edge Chromium) | `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cache\` |
| **Browser form history** | Edge/Chrome/Firefox profile — may contain Epic account email + session cookies |
| **NTUSER.DAT** | Per-user hive — full user-profile registry history |
| **UsrClass.dat** | Per-user class hive |
| **MFT ($MFT)** | Every file that has ever existed — slack entries survive deletion |
| **$LogFile** (NTFS) | Transaction log of recent filesystem ops |
| **$INDX records** | Directory index entries that survive file deletion |
| **$Boot** | Volume serial |
| **$Secure** | File security metadata |
| **Quarantine folders** (Defender / AV) | `C:\ProgramData\Microsoft\Windows Defender\Quarantine\` |
| **Memory dumps** | `C:\Windows\Minidump\*.dmp` + `C:\Windows\Memory.dmp` — can contain cheat DLL memory |
| **Setup logs** | `C:\Windows\inf\setupapi.dev.log` — every driver install |
| **Panther logs** | `C:\Windows\Panther\` — setup/upgrade logs |
| **Search index** | `C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb` |
| **ReadyBoot** | `C:\Windows\Prefetch\ReadyBoot\` — boot optimization traces |
| **MEMORY.DMP** (if crash dump enabled) | Full memory snapshot at crash time |
| **SxS logs** | `C:\Windows\Logs\CBS\CBS.log` — component-based servicing |
| **IoT Enrollment info** | `HKLM\SOFTWARE\Microsoft\Provisioning\` |

### 6.3 — EAC-specific traces beyond [10]

Per [16 telemetry](16-telemetry-endpoints.md):

| Artifact | Path |
|-|-|
| Attestation state | `HKLM\SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS\Attestation` |
| ProductsInstalled | `HKLM\SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS\ProductsInstalled` |
| Platform Quote Keys | `HKLM\SYSTEM\CurrentControlSet\Services\Tpm\PlatformQuoteKeys\EacQuoteKey` |
| ErrRpt_* values | Full list in [16](16-telemetry-endpoints.md) |

### 6.4 — Game-specific traces

| Artifact | Path |
|-|-|
| Fortnite logs | `%LOCALAPPDATA%\FortniteGame\Saved\Logs\` |
| Fortnite config (contains user ID) | `%LOCALAPPDATA%\FortniteGame\Saved\Config\` |
| Fortnite crashes | `%LOCALAPPDATA%\FortniteGame\Saved\Crashes\` |
| Fortnite web cache | `%LOCALAPPDATA%\FortniteGame\Saved\WebCache*\` |
| Epic launcher data | `C:\ProgramData\Epic\EpicGamesLauncher\Data\` |
| Epic launcher logs | `C:\ProgramData\Epic\EpicGamesLauncher\Data\Logs\` |
| Epic Online Services cache | `%LOCALAPPDATA%\EpicGamesLauncher\Saved\DeviceIdCache*` |
| Epic account telemetry cache | `C:\ProgramData\Epic\SocialBackendCache\` |
| Epic launcher install location | `HKLM\SOFTWARE\Epic Games\EpicGamesLauncher` |
| Fortnite Steam shortcut (if streamed via Steam) | Steam shortcuts.vdf |

### 6.5 — Third-party game / streaming overlay traces

| Artifact |
|-|
| Discord logs + install path |
| Discord Rich Presence state |
| Steam install dir + friend list |
| NVIDIA Shadowplay captures (`%USERPROFILE%\Videos\<Game>\`) |
| OBS/streamlabs configs |
| AMD ReLive captures |
| Game bar captures (Win+G) |
| **NVIDIA Container service logs** (`C:\ProgramData\NVIDIA\NVIDIA Container\*.log`) |
| **GeForce Experience tokens** |

---

## Part 7 — EOS / Epic identity stack

Beyond machine identity, Epic specifically tracks:

| Field | Source |
|-|-|
| Epic Account ID (EpicAccountId) | Online auth session |
| Epic Product User ID (EOS_ProductUserId) | Per-product-sandbox identity |
| Epic Device ID | `%LOCALAPPDATA%\EpicGamesLauncher\Saved\DeviceIdCache` |
| Epic launcher install GUID | `HKLM\SOFTWARE\Epic Games\EpicGamesLauncher\AppDataPath` + install-time stamp |
| OAuth refresh tokens | Encrypted in launcher data |
| Session access tokens (JWT) | Memory + launcher data |
| EOS SandboxId (per game) | Per product |
| EOS DeploymentId | Per product |
| Payment method fingerprints (if purchases made) | Server-side only, not readable client-side |
| Linked platform accounts | Steam, Xbox, PSN, Nintendo — linked at account level |
| Friend list | Server-side, cached locally per session |
| Fortnite session continuation tokens | Per-match |
| Battle Pass state | Per-account |

**Account-level HWID binding:** Epic ties specific machine identifiers to the account at signup time + first-time-on-new-hardware moments. Playing from a new HWID on a banned account requires either (a) HWID spoof to match a non-banned HWID, (b) a new account and new hardware altogether.

---

## Part 8 — Cheat-indicator enumeration (expanded from [12])

Additional signals beyond [12 cheat detection](12-cheat-detection.md):

### 8.1 — Hypervisor-specific indicators

| Signal |
|-|
| CPUID hypervisor bit (`CPUID 1 ECX[31]`) |
| CPUID 0x40000000 brand string |
| Hyper-V-specific leaves (0x40000001-0x4000000A) |
| MSR `MSR_IA32_FEATURE_CONTROL` lock state |
| VMX state via `vmread` (requires ring 0, but observable indirectly) |
| APIC ID topology inconsistency |
| Intel PT (Processor Trace) availability vs expected |
| LBR (Last Branch Record) MSR state (`IA32_DEBUGCTL.LBR`) |
| TSC-adjust MSR nonzero |
| Shadow MMIO regions in physical memory |
| Timing: CPUID cost ratio vs rdtsc baseline (detailed in [18](18-etw-ti-and-kernel-hazards.md)) |
| VM-exit cost of specific instructions (cpuid, rdmsr, invlpg, specific port I/O) |
| `rdpmc` behavior (fixed counter availability under HV) |

### 8.2 — DMA cheat indicators

| Signal |
|-|
| PCI config space of every device (vendor/device/subsys IDs) |
| **PCIe capability list walk** — ACS, ATS, PRI, device/link/slot caps |
| Unknown vendor IDs or recent-FPGA vendor IDs (Xilinx, Lattice, Altera) |
| Devices with implausible subsystem IDs (SubVendor = SubDevice, or trivial patterns) |
| IOMMU state — if disabled, DMA attack possible |
| Devices with Bus Master enable bit set but no legitimate reason |
| MMIO regions mapped outside expected ranges |
| USB-C alternate mode / Thunderbolt DMA capability |

### 8.3 — Kmbox / external input indicators

| Signal |
|-|
| USB-connected HID device whose VID/PID matches known kmbox fingerprints |
| Mouse driver chain inspection (as per [04](04-user-mode-agent.md)) |
| HID report descriptor hash matches known kmbox / Arduino-mouse |
| USB device enumeration pattern during session (hot-plug of a "mouse" mid-session is suspicious) |
| Input event timing — kmbox-injected events have characteristic latency to USB polling intervals |

### 8.4 — Screen-reader / capture-card cheat indicators

| Signal |
|-|
| Capture card devices in device tree |
| HDMI/DP output cloning state |
| DWM composition flags |
| Second GPU output in use |
| Frame-capture-rate anomaly (game frames being pulled at non-standard rate) |

### 8.5 — Kernel-callback-based cheat indicators

| Signal |
|-|
| Competing `PsSetCreateProcessNotifyRoutine` entries — CALLBACK_DUMP IOCTL returns these |
| Competing `PsSetLoadImageNotifyRoutine` entries |
| ObCallbacks table — unknown altitudes nearby EAC's altitude |
| CmRegisterCallback entries — unknown callback routines registered |
| Driver images with hashes not in WDAC block list AND not in Microsoft's signed-driver set |
| Manual-mapped drivers (no backing file at recorded path) |

### 8.6 — User-mode cheat indicators

Beyond what [12] covers:

| Signal |
|-|
| LoadLibraryExW calls with non-standard flags |
| LoadLibrary from non-system paths into protected process |
| Manual IAT rebuild patterns (byte signatures of reflective loader IAT fixup) |
| Hash-resolved import patterns (`imul rax, 0x<hash>` + lookup) — the same technique EAC uses, so ironic |
| Suspicious thread creation flags (`CREATE_SUSPENDED` from external caller) |
| Window message hooks (`SetWindowsHookEx` with `WH_*` from non-whitelisted module) |
| Vectored exception handler count increase |
| AddDllDirectory additions from non-game paths |

---

## Part 9 — Kernel objects a spoofer must be aware of

From [spoof.sys](analysis/01-desire-market-emulator.md) + general knowledge:

| Object | What it is |
|-|-|
| `\BaseNamedObjects\EacEmuShm` | Shared memory for user ↔ kernel IPC in the spoof driver |
| `\Instances\XHWIDSpoofer Instance` | Minifilter instance name |
| `\Driver\Disk` | Base disk driver — filtered for serial/model spoof |
| `\Driver\storahci` | AHCI storage driver |
| `\Driver\stornvme` | NVMe storage driver |
| `\Driver\storport` | Storage port driver |
| `\Driver\USBHUB` + `\Driver\USBHUB3` | USB hub drivers |
| `\Driver\BTHPORT` / `\Driver\BTHUSB` | Bluetooth |
| `\Driver\hidusb` | HID over USB |
| `\Driver\SMBUS` / `\Driver\AMDSMBUS` / `\Driver\amd_smbus` | SMBus (for SPD / RAM serial) |
| `\Driver\i801` | Intel SMBus controller |
| `\Driver\smbctrl` | SMBus controller abstraction |
| `\Driver\IntelTA` | Intel Trusted Agent |
| `\FileSystem\Ntfs` / `\FileSystem\refs` | Filesystem drivers (for volume serial manipulation) |
| `\Registry\Machine\SYSTEM\CurrentControlSet\Control\Class\{4d36e967-...}` | **Disk drives** PnP class |
| `\Registry\...\Class\{4d36e968-...}` | **Display adapters** PnP class |
| `\Registry\...\Class\{4d36e96e-...}` | **USB controllers** PnP class |
| `\Registry\...\Class\{4d36e97b-...}` | **SCSI and RAID** PnP class |
| `\Registry\Machine\SYSTEM\CurrentControlSet\Enum\DISPLAY` | Display enumeration |
| `\Registry\Machine\SYSTEM\CurrentControlSet\Enum\MONITOR` | Monitor enumeration |

---

## Part 10 — The TPM attack surface (deep)

Per [15.6](15-driver-raw-offsets.md#156--trust-score-plumbing):

### What EAC requests from TPM

| Operation | Purpose |
|-|-|
| `TBS_Create_Context` | Open a TBS session |
| `TBS_GetDeviceInfo` | TPM version / manufacturer |
| `TPM2_ReadPublic` on EK handle (`0x81010001` typically) | Read EK public — strong identifier |
| `TpmRetrieveEkCertificate` | Retrieve EK cert from TPM NV storage |
| PCR reads (`TPM2_PCR_Read`) on PCRs 0-23 | Measured boot state |
| AIK-signed quote generation | Bind to EAC session |

### PCR meanings (standard)

| PCR | What it measures |
|-|-|
| 0 | Core Root of Trust for Measurement (CRTM), BIOS code |
| 1 | Platform configuration / firmware options |
| 2 | Option ROM code |
| 3 | Option ROM configuration |
| 4 | IPL (Initial Program Loader) code (Windows Boot Manager) |
| 5 | IPL configuration |
| 6 | State transitions and wake events |
| 7 | **Secure Boot policy, DB, DBX, KEK, PK** |
| 8 | Windows OS Loader (winload.efi) |
| 9 | Windows Resume Loader (winresume.efi) |
| 10 | Windows OS Kernel |
| 11 | BitLocker access control (sealing key) |
| 12-15 | Reserved / debugging / deeper kernel |
| 16 | Debug |
| 17-22 | Dynamic Root of Trust (TXT/SVM) |
| 23 | Application support |

### Why PCR 7 matters for EAC

If PCR 7 changes between sessions on the same machine, it means Secure Boot policy / DB / KEK was touched → anomaly. **Loading unsigned drivers changes measured boot → PCR drift → EAC sees inconsistent attestation.**

### Why TPM is "nearly impossible to spoof"

- The EK private key never leaves the TPM. You can't extract it.
- Quotes are AIK-signed, and AIKs are themselves rooted in the EK.
- Even if you virtualize the TPM, the EK of the virtual TPM is different from the physical EK, and Epic's backend binds the EAC session to the EK it saw on signup.

---

## Part 11 — Specific checks summarized by what they catch

| What EAC wants to catch | Checks used |
|-|-|
| User-mode cheat injected into game process | VAD walker, module scan, thread callback, image load callback, pattern scan |
| External memory reader | Handle strip (ObCallbacks), ENUM_HANDLES |
| Cheat kernel driver loaded | DRIVER_LIST + WDAC state, CALLBACK_DUMP, PsLoadedModuleList walk |
| Cheat kernel driver manual-mapped | VAD + no backing file, missing LDR entry |
| Hypervisor-based cheat | Anti-VM (CPUID, APIC, timing), MSR state |
| DMA attack via FPGA PCIe card | PCI config enum, IOMMU state, DMA protection state |
| Kmbox / external input hardware | Mouse driver chain, HID descriptor hash, input anomaly ML |
| HWID spoofer (various quality) | SMBIOS history, TPM attestation drift, ETW-TI violations, cert trust state |
| Debugger attached | Multiple anti-debug (PEB, flags, HWBP, timing, kernel) |
| VM environment | Anti-VM suite |
| Overlay drawing over game | Window scanner + DXGI capture + ML |
| Game memory tampering | Integrity timer (self + game modules) |
| Modified EAC itself | Driver self-hash + agent self-hash |
| Server-sent message tampering | Ed25519 signatures on EAC packets |
| Macro / recoil script | Input distributional ML |
| Trigger-bot pixel sampling | Input time-to-shot, frame-capture ML |
| Impossibly good aim / tracking | Server-side behavioral ML |
| New hardware from banned account | HWID fingerprint hash comparison |

---

## Part 12 — The things not easily spoofed

Hierarchy of "how hard to fake" for common HWID sources, worst-to-best spoofer target:

1. **TPM EK public hash** — near-impossible without clearing physical TPM or hypervisor virt-TPM.
2. **TPM PCR values / attestation quotes** — hypervisor virt only.
3. **SMBIOS values with history matching** — hard but doable with persistent driver.
4. **CPU identifiers (CPUID)** — hypervisor-level only; bare-metal nearly impossible.
5. **ACPI OEM IDs (DSDT, SSDT, OEM strings)** — doable with ACPI table patching at boot.
6. **Permanent MAC via NDIS** — doable with NDIS filter.
7. **Physical disk serial** — doable with storage filter driver.
8. **Volume serial (NTFS boot sector)** — doable but conflicts with Secure Boot + BitLocker.
9. **Monitor EDID** — doable via registry write + display driver filter.
10. **Machine GUID / registry identity fields** — trivial registry writes.

**Operational implication:** a spoofer that only handles items 6-10 looks like a spoofer. A spoofer handling 3-10 is "commercial quality." Item 1-2 requires either TPM clear (destroys BitLocker) or hypervisor (triggers anti-VM).

---

## Part 13 — Summary catalog

Fields to verify in your own live-reverse session against YOUR machine, cross-referenced to the docs:

- Hardware inventory: see Parts 1.1-1.12
- OS inventory: see Parts 2.1-2.5
- On-disk trace inventory: see Part 6
- Kernel surfaces EAC uses: see Part 3
- TPM: see Part 10
- Network: see Part 4
- Timing: see Part 5
- EOS/Epic identity: see Part 7

**Nothing significant is omitted from this catalog as of the current build of the researcher's knowledge.** If you encounter something not listed, (a) it's a very recent EAC addition, or (b) it's a non-EAC side-channel Epic uses outside the anti-cheat pipeline. Either way worth documenting and adding here.

---

**Back to:** [README navigation](../README.md)
