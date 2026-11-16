# 22 — Advanced cheat architectures (deep technical)

The specific mechanics of cheats at each layer above "user-mode DLL." Hypervisor-based cheats with EPT page splitting, SMM cheat architecture, UEFI bootkit layouts, DMA card implementation, GPU-executed reads, scripting engine abuse. Written as mechanics explainers — what each technique actually does at the hardware/kernel level and what EAC's detection surface is for each.

---

## Part 1 — Hypervisor-based cheats with EPT page splitting

The gold standard of cheat stealth as of 2026. Expensive to develop, hard to detect, limited operator population.

### 1.1 — What a type-1 cheat hypervisor is

A thin hypervisor that:
- Installs before or alongside Windows.
- Runs the Windows kernel as a VMX guest (Intel) or SVM guest (AMD).
- Can intercept specific CPU events via VM-exits.
- Uses EPT (Extended Page Tables on Intel) / NPT (Nested Page Tables on AMD) to control what physical memory the guest sees.

### 1.2 — EPT / NPT basics

Two-level translation:
- **Guest virtual → Guest physical** (controlled by Windows).
- **Guest physical → Host physical** (controlled by the hypervisor via EPT/NPT).

The cheat hypervisor sits at the second layer. From Windows' perspective, there's no visible change in how memory works. From the hypervisor's perspective, every memory access can be observed and manipulated.

### 1.3 — Page-splitting trick

The specific technique commercial stealth hypervisors use:

```
For a given guest physical page P:
- When the guest ACCESSES P for READ:    map to host page P' (modified)
- When the guest ACCESSES P for EXECUTE: map to host page P (original)
```

Implemented via EPT permission bits + VM-exit on permission violations:
1. Mark page as execute-only in EPT.
2. On read access → VM-exit → swap EPT mapping to the modified copy, make it read-only.
3. On execute access → VM-exit → swap back to the original executable copy.
4. Optional: single-step with MTF (Monitor Trap Flag) after each access to reset the trap.

**Effect:** when EAC reads a page to verify its hash, EAC sees the **modified** version (because EAC reads it, not executes it). When the CPU executes that page, it sees the **original** executable code. The hash EAC computes matches the "modified" page, which is byte-identical to what EAC expects (because the modification was designed to pass the hash). The actually-executing code has a hook or modification the hash check never sees.

### 1.4 — Classic page-splitting use case

The cheat wants to hook `MmCopyVirtualMemory` to return fake data when EAC's driver tries to read game memory. Flow:

1. Cheat hypervisor identifies the physical page containing `MmCopyVirtualMemory`'s entry.
2. Creates two copies of the page:
   - **Read view** — unmodified, matches EAC's expected hash.
   - **Execute view** — modified with a jump at the function prologue to the cheat's hook.
3. EPT configured: read access → read view; execute access → execute view.
4. EAC's integrity scan of ntoskrnl's `.text` reads through MmCopyVirtualMemory's page → sees unmodified bytes → hash matches expected.
5. CPU executes MmCopyVirtualMemory → sees the modified bytes → jumps to the hook → hook returns fake data to EAC's cross-process-read requests.

### 1.5 — What EAC can observe

EAC catches this via timing + MSR state, NOT via memory content:

- **CPUID timing** ([08 protection stack](08-protection-stack.md)) — VM-exits on CPUID increase its cost. EAC's timing baseline calibration flags.
- **MSR state anomalies** — some hypervisors leak state in MSRs the guest can read.
- **APIC ID topology** inconsistencies.
- **TSC-adjust MSR** nonzero when the hypervisor adjusts TSC to hide its overhead.
- **LBR / Intel PT state** — the cheat hypervisor may use these for its own stepping; their state is observable via `IA32_DEBUGCTL` MSR.
- **PT-mode checks** — RDMSR patterns that vmexit return data that doesn't match bare-metal expected.

Stealth hypervisor developers mitigate these by:
- Accurately spoofing CPUID timing (hard — requires micro-measuring the vmexit cost and padding bare-metal response time to match).
- Clearing TSC-adjust after each vmexit.
- Not using LBR/PT (or clearing after use).

Current 2026 state: a well-written stealth hypervisor is **not caught by individual-session analysis**. It's caught by behavioral ML correlating across sessions — the cheat produces impossibly good aim or trajectory, and over N sessions the statistical signature becomes clear regardless of memory-level stealth.

### 1.6 — Hypervisor install paths

**Install as a boot driver (`ServiceGroup = Boot`):**
- Loads early in boot sequence.
- Before PatchGuard initialization.
- Can enter VMX root mode cleanly.
- Visible as a loaded driver → EAC's `DRIVER_LIST` sees it → flagged.

**Install via BYOVD, late-load:**
- Uses a vulnerable signed driver to map the hypervisor into kernel memory.
- Enters VMX root mode late (after Windows has booted).
- Harder to transition cleanly — Windows may already be in a state that the hypervisor's entry handler doesn't gracefully take over.
- Not visible in LDR (manual-mapped) → caught by `CALLBACK_DUMP` if it registers callbacks, caught by `PsLoadedModuleList` walk otherwise.

**Install via UEFI bootkit:**
- Runs before Windows boots.
- Loads a hypervisor that Windows boots under.
- From Windows' perspective, there's always been a hypervisor.
- Combined with Windows feature detection: Windows sees "Hyper-V is present" and the EAC agent sees the hypervisor brand.
- Spoofable brand strings or complete HV-brand hiding.

### 1.7 — Public hypervisor cheat architectures

Named in research context (not endorsements):

- **"Bluepill"-descended projects** — Joanna Rutkowska's 2006 proof-of-concept inspired many.
- **GhostArea / variants** — commercial private cheat line. Hypervisor-based. 2021-present.
- **DarkEHP / variants** — academic-origin, modified for commercial cheat use.
- **Stealthbyte / SubRosa** — commercial lines, hypervisor + DMA hybrid.

Each costs $500-2000/week retail and rotates faster than EAC catches up.

---

## Part 2 — SMM (System Management Mode) cheats

### 2.1 — What SMM is

- **Ring -2** on x86 (even lower privilege than hypervisor).
- Entered via SMI (System Management Interrupt).
- CPU saves state, jumps to SMM handler in SMRAM.
- SMRAM is physically isolated — OS/hypervisor can't touch it.
- Returns via RSM instruction.

Normal use: BIOS/UEFI uses SMM for firmware-level operations (fan control, thermal management, power state transitions, legacy USB emulation).

### 2.2 — SMM as a cheat primitive

**Capabilities:**
- Read any physical memory (including kernel + hypervisor memory).
- Write any physical memory (within SMM security constraints — depends on firmware).
- Not visible from OS or hypervisor.
- Not interruptible by PatchGuard, HVCI, or any OS-level anti-cheat.

**Install requirements:**
- Firmware vulnerability that allows writing to SMRAM.
- Persistence requires either:
  - UEFI variable-based payload loader.
  - Direct SPI flash modification (physical access or firmware update vulnerability).

### 2.3 — Published SMM attack research

- **"Attacking SMM Memory via Intel CPU Cache Poisoning"** (Duflot et al., 2009).
- **"ThunderStrike"** (Trammell Hudson, 2015) — Mac firmware attack with SMM relevance.
- **Thinkpwn** (2016) — Lenovo laptop SMM exploit.
- **Intel SA-00086** (2017) — ME CSME vulnerabilities that interact with SMM boundary.
- **CVE-2019-0090 / "Downgrade"** — Intel converged security engine issues.
- **CVE-2023-20593 / "Zenbleed"** — AMD side-channel that leaks data across SMM boundary.

### 2.4 — Why SMM cheats are rare in consumer markets

- **Firmware exploit discovery is expensive.** Each OEM's SMM is different; a vulnerability in one Dell firmware doesn't work on HP.
- **Persistence across firmware updates is hard.** Every BIOS update potentially closes the vulnerability.
- **No standard interface** — the cheat code has to know the specific firmware's SMM layout.
- **Legal/ethical lines** — most researchers who find SMM vulnerabilities disclose responsibly.
- **Not needed for most cheat markets** — DMA cheats at $500-2000/wk give similar stealth with much lower engineering cost.

End state: SMM cheats exist in nation-state APT toolkits, not in consumer cheat markets.

### 2.5 — What EAC can observe

Essentially nothing from the OS side. SMM is invisible.

**Indirect signals:**
- **SMI count anomalies** — on some CPUs, SMI entry/exit is counted in a non-privileged MSR. Suspicious if too frequent.
- **Firmware version + vendor** via SMBIOS (if firmware with known SMM vulnerability is in use, that's a soft flag).
- **TPM PCR 0-1** — measures firmware. SMM-cheat-modified firmware changes these values. Drift flaggable.
- **Secure Boot DB/DBX hashes** — if firmware is in a non-standard state, attestation fails.

TPM-based attestation is the main defense Windows has against SMM-level cheats. Windows "Memory Integrity with Trusted Launch" (available on Windows 11 with capable firmware) specifically defends this boundary.

---

## Part 3 — UEFI bootkits for cheat deployment

### 3.1 — The UEFI stack

Boot sequence:
1. Firmware (UEFI) runs.
2. UEFI loads Windows Boot Manager (bootmgr.efi) from EFI System Partition.
3. Boot Manager loads Windows OS Loader (winload.efi).
4. OS Loader loads ntoskrnl + boot drivers.
5. Kernel starts.
6. Services start.
7. User logon.

**UEFI bootkits intercept somewhere in 2-4** — specifically before step 4's kernel integrity verification.

### 3.2 — Bootkit architecture for cheat loading

**Stage 1 — ESP payload:**
- Modified bootmgr.efi OR an additional UEFI driver loaded via `BootOrder`.
- Signed to pass Secure Boot (if possible — requires private key access OR CVE like Baton Drop).
- Runs in UEFI boot services context.

**Stage 2 — Transition hook:**
- Hooks ExitBootServices or similar transition point.
- Preserves hooks across the UEFI → runtime transition.

**Stage 3 — Kernel memory writer:**
- After kernel loads, modifies kernel memory to install the cheat driver's entry points.
- Pre-empts PatchGuard initialization (PatchGuard isn't running yet).
- Registers callbacks the cheat driver needs.

**Stage 4 — Runtime cheat driver:**
- Lives in kernel memory, callbacks wired.
- Operates as a kernel-mode cheat.

### 3.3 — BlackLotus-like deployment

Specifics (publicly documented):
- **CVE-2022-21894 ("Baton Drop")** — bypass Secure Boot via a specific vulnerable Boot Manager version.
- Bootkit signed with a legit Microsoft-signed vulnerable bootmgr that BlackLotus chain-loaded.
- Secure Boot verifies the signed bootmgr → bootkit chain-loads from it → runs with Secure Boot's blessing.
- Post-boot, the bootkit patches winload.efi and kernel in memory.

### 3.4 — Detection

EAC-observable signals:
- **Measured Boot PCR drift** — PCR 4, 5, 7, 8 change. If Epic's backend has baseline PCR values from previous sessions, drift is a flag.
- **HVCI state** — bootkits typically disable HVCI. Reported as flag.
- **Secure Boot policy state** — if bootkit updated DB/DBX, change is reported.
- **Firmware fingerprint anomaly** — SMBIOS + ACPI may have small inconsistencies if bootkit altered them.
- **`BootEfiActiveSec` + `WBCLColdboot` + `WBCLDrtmColdboot`** — the WBCL (Windows Boot Configuration Log) records every measured value. EAC reads these per [spoof.sys](analysis/01-desire-market-emulator.md).

End state: UEFI bootkit cheats work for the single-session execution, but produce a persistent fingerprint anomaly that correlates across sessions. HWID ban eventually fires.

### 3.5 — Persistence economics

- Bootkit requires physical install (one-time admin access).
- Survives OS reinstall (lives in ESP).
- Survives drive wipe if not specifically targeting ESP.
- Removed by: firmware reflash, or by explicit ESP mount + cleanup + Secure Boot DBX refresh.
- Commercial cheat price: $5000+ one-time setup, plus weekly runtime license.

---

## Part 4 — DMA cheats — deep implementation

### 4.1 — The PCIe transaction layer

Every PCIe device speaks three protocols:
- **Configuration transactions** — reading/writing device config space (vendor/device IDs, BARs, etc.).
- **Memory read/write transactions** — accessing device BARs OR host memory (if bus-master bit set).
- **I/O transactions** — legacy, deprecated for most devices.

**DMA = memory transactions where device is initiator and host memory is target.**

### 4.2 — The DMA cheat flow

```
+-------------------+          +--------------+          +---------------+
|  Control PC       |  USB 3.0 |   FPGA DMA   |   PCIe   |  Game PC      |
|  - Game state     | <------> |   Card       | <------> |  - Game proc  |
|    analyzer       |          |              |          |    memory     |
|  - Aim decision   |          |              |          |               |
+-------------------+          +--------------+          +---------------+
                                      |
                                      | Independent USB path
                                      V
                              +--------------+
                              |  kmbox-style |
                              |  input       |
                              |  injector    |
                              +------+-------+
                                     |
                                     V USB HID events
                              +---------------+
                              |  Game PC      |
                              |  mouse/kbd    |
                              |  input stack  |
                              +---------------+
```

Two devices on the game PC:
1. The DMA FPGA card (reads game memory).
2. The input injector (writes mouse/keyboard events).

Both can spoof their identity to appear as legitimate devices.

### 4.3 — PCI config space of a DMA card

**Raw FPGA (unspoofed):**
- Vendor ID: Xilinx `0x10EE`, Lattice `0x1204`, or Altera `0x1172`.
- Device ID: FPGA family + part number.
- Class: often `0x058000` (Other Memory Controller).
- Subsystem: whatever the hardware vendor filled in (often empty).

**Spoofed to look like NVMe SSD:**
- Vendor ID: Samsung `0x144D`, WD `0x15B7`, etc.
- Device ID: specific SSD model.
- Class: `0x010802` (NVMe controller).
- Subsystem: real NVMe subsystem patterns.
- Capability list: NVMe-mandatory capabilities (MSI-X, PCIe Express, etc.).

**EAC detection**:
- Walks PCI topology via its `Devi` module.
- For each device, reads capability list.
- Compares against "what capabilities would this device have if it were real."
- Specific anomalies:
  - NVMe spoof without MSI-X properly configured → flag.
  - NVMe spoof with unusual BAR sizing → flag.
  - Multiple identical subsystem IDs across devices → flag.
- Behavioral anomalies:
  - The "NVMe" never shows up as a block device in Windows → flag.

### 4.4 — Bandwidth considerations

PCIe Gen 3 x1 — approximately 985 MB/s theoretical, ~700 MB/s practical.

For a DMA cheat reading game state:
- Fortnite game state fits in ~50-200 MB of reads per second for comprehensive ESP + aim data.
- Entry-level Screamer (PCIe x1): sufficient but slow (noticeable latency for aim corrections).
- M.2 PCIe Gen 3 x4: comfortable headroom.
- PCIe Gen 4/5 x8+: luxury, used for high-refresh-rate aim operations.

### 4.5 — IOMMU / Kernel DMA Protection

When enabled (`Intel VT-d` or `AMD-Vi`), every DMA transaction goes through address translation that:
- Checks if the target physical address is in a region the device is allowed to access.
- Blocks transactions outside allowed regions.

Windows Kernel DMA Protection uses this for hot-plug devices (specifically Thunderbolt). On PCIe slots, IOMMU protection has to be explicitly configured.

**Attacker response:**
- Install DMA card in a slot that's not IOMMU-protected (cold-plug internal PCIe slot).
- Convince user to disable IOMMU in BIOS.
- Use firmware vulnerabilities to disable DMA remapping without the user knowing.

**Detection:**
- EAC reads IOMMU state. If DMA protection is off and the system has features that normally enable it, flag.

---

## Part 5 — The physical-write / MemProcFS path

Specific publicly-available tooling: **MemProcFS** (ulfrisk).

### What it is

An open-source tool that uses DMA hardware to present remote PC memory as a filesystem on the control PC. "Mount" the game PC's physical memory and browse it like files.

### Technical flow

1. Install Screamer-class DMA hardware in game PC.
2. Run MemProcFS on control PC.
3. MemProcFS configures FPGA to issue PCIe memory reads via `WinPcap`-style tooling.
4. Memory is enumerated: every process, every thread, every module.
5. Data is accessible as files: `/proc/4567/memory.dmp` is process 4567's memory, readable as an image.

### Cheat use

Trivial to write a user-mode program on the control PC that opens `/proc/<game_pid>/memory.dmp`, parses game structures (player positions, weapon states), and outputs ESP coordinates.

### Detection

Game PC side: completely invisible. No process, no driver, no hook. The reads happen on the PCIe bus.

Behavioral: the control PC acts on information faster than any human could reasonably obtain. Behavioral ML catches this over N sessions.

---

## Part 6 — GPU-executed cheats (the exotic one)

### 6.1 — Why it's theoretically interesting

- The game's rendered frame lives in GPU memory.
- CUDA/OpenCL/DirectCompute can execute on GPU alongside the game.
- GPU memory access from a sibling process doesn't go through CPU → doesn't trigger EAC's user-mode scans.

### 6.2 — The practical architecture

```
Game Process:
  CPU → D3D11/DXGI → GPU
                      |
                      |  Rendered frames
                      V
                  GPU Memory

Cheat Process (sibling):
  CPU → CUDA API → GPU
                      |
                      |  Compute kernels read framebuffer
                      V
                  Analysis results back to CPU
```

Specific implementation:
- Cheat process attaches to GPU as a CUDA context.
- Uses CUDA to enumerate textures (via `cudaGraphicsD3D11RegisterResource` or vendor-specific APIs).
- Finds the game's framebuffer / specific textures.
- Reads frame data.
- CUDA kernel analyzes frame for enemies.
- Returns ESP data to cheat's CPU side.
- Overlay draws result.

### 6.3 — Specific CUDA/OpenCL primitives of interest

- `cudaGraphicsD3D11RegisterResource` — register a D3D11 texture with CUDA.
- `cudaGraphicsMapResources` + `cudaGraphicsSubResourceGetMappedArray` — get memory handle.
- `cudaMemcpy` / `cudaMemcpyAsync` — read the texture data.

### 6.4 — Detection surface for EAC

- Enumerate GPU processes via NVAPI (`NvAPI_GetProcessList`).
- For each GPU process, check if it's a whitelisted game process.
- Non-whitelisted GPU processes while the game is running → flag.

Edge cases:
- NVIDIA GeForce Experience, Steam overlay, Discord overlay all legitimately use GPU — EAC's whitelist handles these.
- Browser windows with hardware acceleration — whitelist.
- Cheat processes that have no obvious signature on the GPU side — harder to detect.

### 6.5 — Why it's rare in deployed cheats

- Setup complexity is high; CUDA context sharing across processes is finicky.
- Game-specific texture layout knowledge required.
- Easier to just run a user-mode cheat and read process memory directly (if you have a way to defeat the handle strip).

Published as PoC in academic papers but not widely deployed.

---

## Part 7 — Process-manipulation technique catalog

Each of these has been used in cheat deployment. EAC's countermeasures are current-build state.

### 7.1 — Process hollowing

1. `CreateProcess` in `CREATE_SUSPENDED`.
2. `NtUnmapViewOfSection` on the suspended process's image base.
3. `VirtualAllocEx` at the same base.
4. `WriteProcessMemory` the cheat image.
5. Set new entry point via `SetThreadContext`.
6. `ResumeThread`.

**Catch:** PE header at base, ImageFileName in EPROCESS, LDR entries all become inconsistent → VAD walker + integrity scan catches.

### 7.2 — Process Doppelgänging

Covered in [21 Part 5](21-real-exploits-case-studies.md). TxF-based transient view trick.

**Catch:** process memory hash doesn't match on-disk file hash → integrity check catches.

### 7.3 — Process Herpaderping

Covered in [21 Part 5](21-real-exploits-case-studies.md). Modify file after section creation.

**Catch:** file-on-disk change observed via NTFS filter / MFT timestamp drift.

### 7.4 — Early Bird APC injection

Covered in [21 Part 5](21-real-exploits-case-studies.md). APC queued before initial thread resumes.

**Catch:** ETHREAD.Tcb.ApcState inspection + ETW-TI `NtQueueApcThread` events.

### 7.5 — Thread hijacking

1. Open existing thread with `THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT`.
2. `SuspendThread`.
3. `GetThreadContext`.
4. Save current RIP.
5. Set RIP to jump to cheat code (allocated separately).
6. `SetThreadContext` + `ResumeThread`.
7. Cheat code runs, eventually jumps back to saved RIP.

**Catch:** `THREAD_SET_CONTEXT` stripped by ObCallbacks on protected process. External process with thread handle gets `ACCESS_DENIED`.

### 7.6 — Atom bombing

Covered in [21 Part 5](21-real-exploits-case-studies.md).

**Catch:** ETW-TI + ObCallbacks.

### 7.7 — Ghost writing

Allocate executable memory in target, write code, but never create a thread. Instead, rely on a legitimate thread in the target to hit a specific function pointer (that you've overwritten to point to your code).

**Catch:** write-to-target requires PROCESS_VM_WRITE → ObCallback strip.

### 7.8 — Memory-mapped file injection

1. `CreateFileMapping` with cheat code.
2. `NtMapViewOfSection` on target process's handle.

**Catch:** target process handle still requires PROCESS_VM_OPERATION → ObCallback strip.

### 7.9 — Section-spray via named sections

A legitimate app creates a named section → cheat opens it by name → maps into own address space → shares memory with target without opening a handle.

**Catch:** only works if the game opens a named section itself; most games don't.

### 7.10 — Reflective DLL injection

1. Allocate executable memory in target.
2. Write a shellcode loader + DLL image to the memory.
3. Create thread at the loader's entry.
4. Loader parses DLL headers, fixes imports, calls DLL entry.

**Catch:** VAD-walker catches `VadPrivate` with executable protection; no LDR entry.

### 7.11 — Manual DLL mapping (ulfrisk's MapLibrary-style)

Mimics LoadLibrary without going through LDR:
1. Allocate memory for DLL in target.
2. Copy PE to memory.
3. Resolve imports by walking kernel-known IAT (requires kernel-side cooperation).
4. Fix relocations.
5. Call `DllMain(DLL_PROCESS_ATTACH)`.

Variation: inject via a kernel-mode writer, so step 2's `WriteProcessMemory` bypasses ObCallback strip.

**Catch:** VAD-walker sees Image-type VAD with no LDR entry → "unlinked image" flag.

### 7.12 — Section-image via NtCreateSection

1. `NtCreateSection` with `SEC_IMAGE` on cheat DLL file.
2. `NtMapViewOfSection` into target.
3. Section is now marked `Image` → shows up in VAD as Image type.

**Catch:** path resolution — section comes from a file whose path EAC can hash. If path's not in LDR or path matches rules.bin suspicious patterns → flag.

### 7.13 — ETW manipulation to bypass TI

Advanced: register as a Protected Process Light (PPL) subscriber to the TI provider, consume events before EAC does, selectively drop events relating to the cheat's own operations.

**Catch:** PPL requires specific signing; cheat doesn't have it. Attempts to register without proper signing fail. Attempts to subvert the provider itself trigger kernel integrity failures.

---

## Part 8 — Advanced debugging / observation techniques (cheat-adjacent)

Used by cheat developers for live reverse engineering of EAC itself.

### 8.1 — HyperDbg

Hypervisor-based debugger. Can set breakpoints that don't appear in Dr0-Dr3. Can step past VMProtect-virtualized code one handler at a time. Can read protected process memory without PROCESS_VM_READ by just reading physical memory.

Usage against EAC:
- Load HyperDbg before EAC service starts.
- Place EPT-based hooks on EAC's VMP entry gadgets.
- Trace handler-by-handler.
- No visible debugger state from EAC's checks.

### 8.2 — Intel PT (Processor Trace)

CPU feature that emits control-flow events to a ring buffer. A sibling process can enable PT on a game process and reconstruct the executed instruction stream.

Cheat-adjacent use: read game state via inferred control flow (which opponent the player is aiming at based on which code paths executed).

Also useful for reversing: trace EAC's handler execution to understand the VM.

Detection: `IA32_DEBUGCTL` MSR state. If PT is active on a protected process and the operator isn't a signed tracing tool, flag.

### 8.3 — Last Branch Record (LBR)

Lightweight control-flow tracing via MSR state. Same category as PT, lower overhead, less coverage.

### 8.4 — DMA-assisted live debugging

Use DMA hardware (Screamer) to read EAC's memory in real time without any OS footprint.

Technique:
1. Game PC is running EAC + Fortnite.
2. Control PC has Screamer card in game PC, runs MemProcFS.
3. Attach IDA Pro's remote debugger to MemProcFS → IDA operates on live memory of EAC's agent.
4. Set software breakpoints via memory writes — if EAC's integrity check catches, back off and use hardware breakpoints via DMA-assisted Dr0 writes.

### 8.5 — Side-channel memory reading

For reading very-well-protected memory without triggering any detection:

- **Prefetch side channel** — measure cache behavior of specific addresses to infer their contents.
- **Branch target prediction** — Spectre-style attacks that could leak protected state.
- **Row hammer** — DRAM-level bit flips, not quite side-channel but adjacent.

Rare in deployed cheats; published in academic security.

---

## Part 9 — Scripting-engine cheat architectures (where exposed)

Not Fortnite-specific but worth cataloging. Each major scripting engine in gaming:

### 9.1 — Lua (used in many MMOs, some FPS)

Attack: find a Lua binding that accepts a file path, pass a path to `/proc/<pid>/mem` or equivalent.

Caught by: engine sandbox (restrict which paths Lua can access), EAC doesn't need to — the engine owns this.

### 9.2 — JavaScript (Electron-based games, modding APIs)

Attack: use Electron's Node.js integration (if enabled) to `require('child_process').exec(...)`.

Caught by: Electron's `nodeIntegration: false` setting disables this path. Games that don't set it are vulnerable.

### 9.3 — Verse (Fortnite UEFN)

Sandboxed. Current implementation doesn't expose primitives useful for cheat execution in Battle Royale mode. UEFN Creative mode has Verse but it's scoped to its sandbox.

### 9.4 — Blueprint (UE scripting)

Compiled at build time. Runtime Blueprint execution is scoped to game logic, no direct memory access primitives.

### 9.5 — Pattern — scripting-engine abuse history

For reference: Minecraft's Lua-adjacent mods, Garry's Mod addons, Roblox Lua sandbox escapes — all have specific attack histories. Fortnite not vulnerable via this class.

---

## Part 10 — Attack synthesis — combined architectures

The highest-end cheats combine multiple techniques:

### Example commercial cheat architecture (circa 2026)

```
Boot:
  UEFI bootkit (persistence)
    → loads hypervisor driver pre-OS
      → Windows boots as VMX guest
        → EAC loads normally
          → Cheat's hypervisor hides from EAC's anti-VM checks via timing spoof
        → Cheat kernel driver loaded into kernel memory by hypervisor
          → No LDR entry, no callbacks registered that EAC sees
            → Patches EAC's pin-check function via EPT page-split
              → MITM EAC's TLS traffic, read session state
                → Spoof HWID queries via ACPI + SMBIOS + storage filter
                  → EAC's env_worker reads return consistent spoofed values

Runtime:
  Game runs normally
    → Cheat hypervisor hooks CR3 switches to track process boundaries
      → Reads game memory via EPT-level access without PROCESS_VM_READ
        → Computes ESP/aim decisions
          → Writes via another EPT-level page-split to inject input into game's input ring buffer

Operator:
  Buys cheat for $2000/month
    → Gets installer + weekly key update
      → Discord support channel for troubleshooting
```

### What survives detection

- Memory-level: hypervisor EPT magic hides everything.
- Kernel callback-level: no cheat callbacks registered.
- Driver-list level: cheat driver not in `PsLoadedModuleList`.
- VAD-level: cheat code lives in kernel memory, game process's VAD is clean.
- TPM-level: PCRs may drift (UEFI bootkit modifies measured boot). **This is the eventual loss condition.**
- Behavioral: aim statistics across hundreds of matches eventually correlate.

End state: lives for 3-6 months per hardware setup. HWID ban. Operator buys new hardware OR migrates to a different account chain.

---

## Part 11 — Where the "nothing works" line is

Direct take, after everything above:

**For the $5 public cheat tier:** nothing works for more than a session. Modern EAC's user-mode scans catch unprotected injection + overlay + hooks in under a minute. Soft-ban or kick is the common outcome.

**For the $50 private cheat tier:** works for days-to-weeks. Uses BYOVD for kernel access, spoofs HWID at user-mode level, rotates on detection waves.

**For the $500 hypervisor tier:** works for weeks-to-months. UEFI persistence + hypervisor stealth. Eventually behavioral ML catches, then HWID ban.

**For the $2000+ DMA tier:** works indefinitely at low-skill expression. Weeks at high skill. Eventually behavioral ML catches.

**For the "nation-state tier" (SMM + firmware exploit + full stealth):** essentially undetectable. Not sold commercially. Exists in APT toolkits, not consumer cheats.

**The reason most cheaters get caught:** not because the cheat was bad, but because they got greedy with it. Statistical aim perfection over hundreds of sessions is the detection.

---

## Part 12 — Closing — what this means for the research itself

Reverse engineering EAC isn't about "finding the one exploit." It's about mapping the entire detection surface so that:

- Defenders know what signals to prioritize.
- Legitimate security researchers know what Epic's model looks like.
- Private-server implementers know what has to be replicated on their backend.

Each of the techniques in this document is public research. Nothing here is a cheat distribution. Treat it as a security-research map, which is what the rest of the repo aims to be.

---

**Next:** [23 — Small-detail fixes & clarifications](23-small-detail-fixes.md)
