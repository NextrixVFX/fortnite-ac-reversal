# C — Cheat detection surface

The specific detection surface EAC maintains for things that live in cheats. Categorized by what the cheat does.

---

## C.1 — Kernel driver indicators

What EAC's driver looks at in other drivers:

### Direct identification

| Check | Section in rules.bin |
|-|-|
| Image hash match | `0x30` |
| Name match | `0x31` |
| Signer cert thumbprint match | `0x32` |

### Environment

| Check | Flag |
|-|-|
| WDAC block-list state (current-build `DRIVER_LIST` returns this) | high severity |
| Authenticode signature validity | moderate |
| Image path — non-standard paths (UNC `\\.\`, temp directories, downloaded content) | moderate |
| Load reason — current-build EAC compares load time to known "bulk boot load" window vs ad-hoc late load | moderate |

### Manual-map indicators

- `PsLoadedModuleList` entry missing when image exists in `PsLoadedModuleList`'s backing allocation (unlink patterns)
- Driver image not present on disk at the recorded path
- Image lacks a valid PE header structure (corruption as anti-analysis)

### The rules list is live

Rules.bin driver sections carry a running list of "we have seen this driver used by cheats" entries. The list updates via `RULES_UPDATE` pipe opcodes without an EAC version update.

### Known-bad signed drivers (BYOVD set)

Drivers with valid signatures that contain exploitable primitives (arbitrary read/write, map physical memory, etc.) that cheat loaders abuse. Microsoft's WDAC block list contains the major ones:

- `RTCore64.sys` (MSI Afterburner)
- `GPC-U64.sys`
- `ATSZIO64.sys`
- `GDRV.sys` (Gigabyte)
- `DBUTIL_2_3.sys` (Dell)
- …many more

EAC's `DRIVER_LIST` IOCTL marks each loaded driver with its WDAC-match state. Match → flag high severity, even if the signature is still technically valid.

### Hypervisor-based cheats

A type-2 or stealth type-1 hypervisor that reads game memory from the host and writes results to a channel the cheat process reads. Detected by:

- Anti-VM signals (from [08](08-protection-stack.md))
- APIC ID topology anomalies
- CPUID timing baseline deviation
- CPUID leaf 0x16 (frequency) returning unexpected values
- rdtsc timing of operations that would cause vmexits under a hypervisor (CPUID, MSR reads, specific port I/O)

A well-written stealth hypervisor (SimpleVisor-derived, commercial offerings) can defeat most of these individually. EAC's answer: raise them to "suspicious" rather than "fatal" and let server-side ML correlate over multiple sessions. A single session of "all VM indicators look fine but the timing is 0.5% off baseline" doesn't ban; 300 sessions with the same tiny offset correlated against win-rates does.

---

## C.2 — Injection indicators

What EAC looks at for cheat DLL injection:

| Indicator | Source |
|-|-|
| **New thread in protected process with start address not in any module** | Shellcode — flag hard |
| **New thread with start address not in whitelisted module** | Flag |
| **VAD entry mapped as Image not in `PEB->Ldr`** | Unlinked module — flag |
| **VAD entry with executable + private protection** | Raw code memory — flag |
| **Transient-executable regions** (R/W at snapshot T, R/X at T+2s) | Runtime unpacking — flag |
| **APC queue entries from non-whitelisted senders** | Current-build inspects `ETHREAD->Tcb.ApcState` for suspicious queue contents. APC injection leaves a queued APC entry at the point of injection |
| **Reflective loader stubs** | Characteristic byte patterns (fnvhash lookups, manual IAT fixups) — rules.bin pattern sections catch them |
| **DLL side-loading / proxy DLLs** | Current-build EAC tracks the dependency tree of game modules and flags if a system DLL is resolved from a non-system path (search-order abuse) |
| **Thread hijacking** | `SetThreadContext` from non-whitelisted caller on a protected process thread → thread strip mask + handle open attempt log |
| **Manual-map shellcode in the game process's own allocations** | Pattern matched |

### The common 2026 cheat pattern

Manual-mapping a cheat DLL into the game process via a kernel-mode writer, bypassing the ObCallback strip by not using `OpenProcess` at all. This leaves:

- A VAD entry (type `Image` if the manual-mapper was polite, type `Private` if not)
- No LDR entry
- Thread(s) with start addresses in the mapped region (if the cheat started its own threads), OR a hijacked existing thread (if not)
- IAT entries resolved manually

**The VAD walker catches this on the first scan tick after the map.**

### Cheat counter-measures and how EAC counters the counter

| Cheat approach | EAC response |
|-|-|
| Map as RW initially, flip to RX momentarily to run | Transient executable detector catches the flip |
| Use existing executable VADs (hollowing a legit module) | Integrity timer catches the `.text` hash change |
| Run cheat code from pure data references with ROP | Expensive, slow, limited in what you can actually do — mostly research territory |

---

## C.3 — Hooking patterns

What EAC detects:

| Hook type | Detection |
|-|-|
| **Inline hooks in system DLL `.text`** | Direct byte diff via hook detector against bundled baselines |
| **IAT hooks in game modules** | Periodic export-pointer re-resolve checks that cached pointers match current `GetProcAddress` |
| **EAT hooks** | Same mechanism from the other direction |
| **`KiUserCallbackDispatcher` hijack** | Current-build checks dispatcher's first few bytes against expected prologue |
| **Vectored exception handlers registered by non-whitelisted callers** | `AddVectoredExceptionHandler` leaves a global list the agent walks |
| **HWBP-based hooks** | `Dr0..Dr3` inspection via `GetThreadContext` (same mechanism as anti-debug) |
| **Instrumentation callback hooks** | `ProcessInstrumentationCallback` nonzero without EAC's knowledge → flag |
| **PT (Processor Trace) / LBR abuse** | Rare, but current-build queries MSR `0x1D9` (`DEBUGCTL`) via the driver to detect LBR active unexpectedly |

### Why "hook briefly" has a shelf life

The hook detector runs on a ~2-5 second rotation. So a cheat that hooks for 500ms, does its thing, unhooks for 2 seconds, hooks again has **maybe a 25% chance per cycle of being caught**. Over a match's worth of ticks that's effectively guaranteed.

---

## C.4 — Game-state manipulation indicators

Reading game memory from outside the process (which the handle strip prevents directly, so this moves kernel-side) can be caught via telemetry **if the cheat's visible effects correlate:**

- Impossibly consistent trajectory tracking (ML on movement data)
- Sub-tick reactions (ML on input vs event timing)
- Occluded-target reactions (ML on fire-events against line-of-sight info the server knows)

**Inside the process, memory reads are invisible** — nothing gets flagged just for reading. The flag path is behavioral: once the cheat uses what it read, server-side correlation catches it.

### Trigger-bot pixel sampling

(Reading screen pixels to detect a colored target region, then auto-firing.)

Caught via:

- Input-anomaly detector's time-to-shot-after-input pattern
- Current-build frame-capture ML looking for aim-circle overlays even if the circle isn't rendered to the client (sampling via DXGI capture of a region)
- Pixel-reader code paths read from the swapchain — the agent doesn't instrument this directly, but the input ML correlates

### Macro input

(Hardware or software that generates recoil-compensation mouse patterns.)

Caught by the input anomaly detector's distributional analysis. Real human recoil compensation has characteristic noise; macros don't.

---

## C.5 — External / hardware-assisted cheats

These don't inject into the game process at all. They:

- Read memory via DMA (a PCIe card with an FPGA doing arbitrary PCIe reads without CPU involvement), or
- Operate purely visually via a capture card + second PC setup, or
- Inject input via a hardware device (kmbox, Arduino-based mouse injectors)

EAC's reach here is limited.

### DMA attacks via PCIe cards

Current-build EAC enumerates PCI devices via its driver, reads each device's PCI config space, hashes vendor/device/subsystem IDs and the capabilities list.

- Known FPGA DMA cards (common chipsets are Xilinx 7-series FPGAs) have characteristic config spaces.
- Rules.bin can block specific vendor IDs.
- Counter from the DMA side: spoof the PCI config space. High-end DMA setups do this. Detection becomes probabilistic.

### Kernel DMA Protection / VT-d / IOMMU state

EAC reports whether DMA Protection is enabled.

- Systems with it enabled → DMA attacks neutralized at hardware level.
- Systems without it → vulnerable.
- Cheater running a DMA setup typically has to disable DMA protection. EAC reports this. Combining "no DMA protection" + "generic performance anomaly" + "win rate outlier" correlates.

### kmbox / external mouse injectors

- Input anomaly detector sees the input stream.
- kmbox-style devices try to pass themselves as legit mice at the USB level.
- Mouse driver chain inspection (current-build) tries to identify the chain of driver objects behind the user-input path.
- kmbox typically connects as a standard HID mouse → driver chain looks normal.
- Detection falls back to input stats.

### Capture card + second-PC setups

Frame-grab from first PC into second PC's inference pipeline, aim commands sent back via kmbox.

- Game PC's EAC agent sees only input events coming in.
- Actual cheat logic is on another machine.
- **Input anomaly is the only detection surface here.**
- This is the hardest cheat category to catch.
- Current-build input ML is specifically trained on these patterns, with mixed success.

---

## C.6 — Signature-based patterns in rules.bin

Rules.bin ships thousands of specific byte patterns targeting known cheat frameworks:

- Manual-mapper boilerplate (reflective-loader stubs, IAT fixup loops)
- Common cheat UI framework strings (ImGui class names and strings, if the overlay class got through the window scanner)
- Popular trainer frameworks' signature constants
- Cheat loader PE header anomalies (TLS callback positions, section-name patterns)
- DMA-card driver fingerprints (for DMA setups that install a driver on the game PC side)
- SMBIOS spoofer fingerprints (known-fake vendor strings)

Pattern matching runs per module load and periodically against each VAD. This is one reason the agent's VAD-scan workload is nontrivial — it's running a few hundred patterns against each executable region.

---

## Detection category summary

| Cheat architecture | Primary detection | Secondary |
|-|-|-|
| In-process DLL (classic) | VAD scan, module scan, handle-open log | Thread scanner, hook detector |
| In-process manual-mapped | VAD walker (ground truth) | Transient-exec detector, entropy check |
| In-process hollowing | Integrity timer | Pattern scan on hollowed region |
| Kernel driver (BYOVD) | `DRIVER_LIST` + WDAC state | `CALLBACK_DUMP` |
| Kernel driver (manual-mapped) | `CALLBACK_DUMP` (if registers callbacks) | VAD scan in game can't see it; relies on behavioral correlation |
| Hypervisor cheat | Anti-VM (CPUID timing, APIC, HV brand) | Behavioral correlation |
| External PCIe DMA | PCI config space enum + config hash | Behavioral correlation |
| kmbox / external input | Mouse driver chain inspection | Input anomaly ML |
| Capture-card second-PC | Input anomaly ML only | — |
| Trigger-bot pixel sampler | Input time-to-shot + frame-capture ML | — |
| Macro / recoil script | Input distributional ML | — |

**The pattern:** EAC catches client-process anomalies. Fortnite's server-authoritative checks catch game-state anomalies. Behavioral ML correlates across both. External cheats evade EAC but can't evade game-state checks because the cheat has to affect game state to be useful.

---

**Next:** [D — EAC emulation](13-eac-emulation.md)
