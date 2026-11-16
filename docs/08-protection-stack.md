# 08 — Protection stack (VMProtect, custom VM, anti-debug, anti-VM, anti-dump, IAT)

The part that will slow your reversing down the most. Everything in this doc exists to make the agent harder to read, dump, hook, or lie to.

---

## VMProtect 3.x

Primary obfuscator on the agent DLL and the driver. VMProtect virtualizes selected functions by compiling them to a bytecode and shipping an interpreter that runs the bytecode.

- **Ultra-mutation enabled** — each handler has 2-8 semantically-equivalent realizations, randomly chosen per build.
- **Import protection enabled** — IAT is scrambled, imports resolved through an intermediate stub.
- **Not everything virtualized** — virtualizing all code would make the DLL unreasonably slow. Only sensitive routines get VMP'd:
  - anti-debug checks
  - anti-VM checks
  - the integrity timer
  - the pin check
  - the session auth
  - SMBIOS fingerprint capture (current build)

The rest is plain native code — obfuscated but tractable.

### Devirt workflow

1. **Dump the DLL from memory** after init. [Scylla](https://github.com/NtQuery/Scylla) to rebuild IAT from the resolved pointers.
2. **Identify virtualized regions** by their entry gadget — VMProtect leaves a characteristic prologue (a push followed by a jump into what looks like a dispatcher).
3. **NoVmp** each virtualized function. VTIL IL dumps out.
   - Repo: [`can1357/NoVmp`](https://github.com/can1357/NoVmp)
   - Expect 70-85% coverage. The uncovered handlers are usually ultra-mutation variants NoVmp hasn't seen yet.
4. **Hand-lift residual handlers** — trace symbolically with triton or by hand with unicorn-engine. Identify the semantic (`vAdd`, `vXor`, `vShl`, `vReadMemQ`, `vCall`, etc.), add to your handler table, re-run.
5. **VTIL has a C exporter.** Output is ugly but readable.

### Handler primitives

Standard VMP vocabulary:

```
vPushReg, vPopReg, vAdd, vSub, vXor, vNor, vMul, vDiv, vShl, vShr,
vReadMemB, vReadMemW, vReadMemD, vReadMemQ, vWriteMem*, vJmp, vJcc,
vCall, vRet, vPushImm, vPopFlag, vCpuid, vRdtsc
```

### Ultra-mutation examples

`vAdd` can be any of:

```
a = a + b
a = -(-a - b)
a = (a ^ b) + 2*(a & b)
a = (a | b) + (a & b)
```

Which makes handler-matching by instruction pattern fragile. Match by semantic.

---

## Custom VM layer (on top of VMProtect)

Current builds wrap 2-4 sensitive routines in a second, simpler custom VM:

- environmental fingerprint capture
- pin check
- session-auth signing path

### Spotting it

- No VMProtect entry gadget.
- Has a classic "fetch byte from table, switch on byte, execute handler" loop.
- Opcode table of 30-60 entries.

### Reversing it

Easier than VMProtect — one layer, no mutation.

1. Identify the opcode table (constants referenced by the loop).
2. Label each handler by behavior.
3. Dump the embedded bytecode and read it like any other disassembly.

---

## Control-flow flattening

On top of both layers. Dispatcher-state machine:

```c
int state = INIT;
while (true) {
    switch (state) {
        case  7: /* block A */ state = 13; break;
        case 13: /* block B */ state =  2; break;
        case  2: /* block C */ state = -1; break;
        case -1: return;
    }
}
```

Unflatten with [`dnpushme/DeFlat`](https://github.com/dnpushme/Deflat) or a triton script. Heuristic: symbolic-execute the dispatcher keeping track of which case transitions to which, reconstruct the natural CFG.

---

## Anti-debug (continuous, not just init)

EAC runs all of these continuously throughout the agent's lifetime.

| Check | Mechanism |
|-|-|
| `PEB.BeingDebugged` | Classic. Still checked. |
| `NtGlobalFlag` | Heap debug flags set → debugger |
| Heap flags | Same idea, different place |
| `ProcessDebugPort` | `NtQueryInformationProcess`; nonzero port → debug |
| `ProcessDebugFlags` | Same; zero → debug |
| `ProcessDebugObjectHandle` | Same; nonzero → debug |
| HWBP | `GetThreadContext` → `Dr0..Dr3` nonzero |
| rdtsc timing | Delta between two nop sequences; too large = being single-stepped |
| Kernel debugger | `NtQuerySystemInformation(SystemKernelDebuggerInformation)` |
| `ThreadHideFromDebugger` consistency | Hidden flag set but debug port still showing → inconsistent debug state |
| `ProcessInstrumentationCallback` | **New in current** — zero means nobody has the kernel-callback instrumentation hook |

Each check nudges a cumulative suspicion score. No single check is a ban on its own.

---

## Anti-VM

| Check | Mechanism |
|-|-|
| CPUID 0x1 ECX bit 31 | Hypervisor-present bit |
| CPUID 0x40000000 brand | `VMwareVMware`, `KVMKVMKVM\0\0\0`, `Microsoft Hv`, `XenVMMXenVMM`, `VBoxVBoxVBox`, `QEMU\0\0\0\0\0\0\0\0`, `TCGTCGTCGTCG`, `bhyve bhyve ` |
| Registry probes | VMware Tools, VBox Guest Additions, Hyper-V Integration Services, Parallels Tools |
| Device probes | `\\.\VBoxMiniRdrDN`, `\\.\pipe\VBoxTrayIPC`, `\\.\vmci`, `\\.\prl_pci` |
| MAC prefix | `00:05:69`, `00:0C:29`, `00:50:56` (VMware); `08:00:27` (VBox); `00:03:FF` (Hyper-V); `00:1C:42` (Parallels) |
| Timing | CPUID cost under virtualization vs native. rdtsc delta across a cpuid, compared against cached native baseline. |
| **APIC ID topology** | **New.** Real hardware APIC IDs have expected topology; many hypervisors return 0 or linear sequences. Anomalous topology flags. |
| **CPUID leaf 0x16 frequency** | **New.** Must return nonzero on real modern hardware. Many hypervisors return zeros. |

None fire immediately. Score accumulates. Backend decides.

---

## Anti-dump

| Technique | Effect |
|-|-|
| Erase PE header after init | Zero `MZ`/`PE` magics in the dumped image. Naive dumpers get garbage at the base. |
| Encrypt `.text` back to packed after sensitive execution | "Snapshot of running agent" is lossy. |
| Continuous self-hash via integrity worker | Paused process with modified `.text` → next tick catches it. |
| `PAGE_EXECUTE_WRITECOPY` on specific regions | **New in current** — CoW breaks naive `.text` patches. |

---

## IAT protection via name hashing

Instead of calling `LoadLibraryA` directly, EAC builds its own import table at init:

```c
typedef struct {
    ULONG hash;      // djb2 or fnv1a of "LoadLibraryA"
    PVOID resolved;
} EAC_IMPORT;

EAC_IMPORT g_imports[128];

void eac_resolve_imports(void) {
    for (int i = 0; i < 128; i++) {
        g_imports[i].resolved = eac_find_by_hash(g_imports[i].hash);
    }
}
```

Calls look like:

```c
((LPVOID(WINAPI*)(LPCWSTR))g_imports[LLW_IDX].resolved)(L"user32");
```

### Reversing it

1. **Find the hash function.** Hash function constants:
   - djb2 init: `5381`
   - fnv1a init: `0x811c9dc5`
2. **Precompute hashes for every export** in `ntdll`, `kernel32`, `kernelbase`, `user32`, `d3d11`, `d3d12`, `dxgi`, `winhttp` (new in current — HTTPS transport), `gdi32`, `gdi32full`.
3. **Script IDA** to replace `g_imports[i]` references with the matching API name based on the stored hash.

Once done, the agent becomes dramatically more readable. Most of the "wtf why is this just calling a global pointer" confusion evaporates.

---

**Next:** [09 — EOS variant delta](09-eos-variant.md)
