# 02 — Kernel driver (`EasyAntiCheat.sys`, current build)

The trust root. The user-mode agent could be lied to by anything in userspace, so EAC's design is "whenever something is security-sensitive, ask the driver." The driver observes the system through legal kernel callback APIs — no inline hooking of ntoskrnl, no SSDT shenanigans, nothing PatchGuard would blow up on. The user-mode agent is really a reporting agent that bubbles the driver's observations to Epic's backend.

---

## DriverEntry

Predictable sequence.

### 1. Self image check

Hash own `.text`, compare to baked-in SHA256, bail on mismatch. Catches naive "patch the sys on disk" attacks, which are useless anyway because the file has a WHQL cross-signature, but the check is there for completeness.

### 2. Kernel API resolution by name

Older builds (pre-2019) had static imports — open in IDA, fat imports list pointing at `ntoskrnl.exe`. Current builds have maybe five imports; everything else is resolved at runtime via `MmGetSystemRoutineAddress`, cached in a global struct, XORed with a per-boot cookie so a kernel memory snapshot doesn't leak a clean pointer table.

Why? Partly so you can't grep statically for "which kernel calls does this driver make." Mostly to slow down reversers. It works for a few hours per build until someone writes the xref script.

### 3. Device + symlink

```c
IoCreateDevice(drv, sizeof(DEV_CTX), <randomized name>,
               FILE_DEVICE_UNKNOWN, 0, FALSE, &g_devObj);
IoCreateSymbolicLink(L"\\DosDevices\\EasyAntiCheat", <device name>);
```

Device name has a random suffix on current builds. Symbolic link name is stable because the user-mode agent needs to `CreateFile` it.

Cheat devs have tried opening the symlink from their own tools to probe IOCTLs. EAC counters by rejecting any client that can't present a signed session blob proving it was launched by the authenticated EAC user-mode agent.

### 4. Dispatch

```c
drv->MajorFunction[IRP_MJ_CREATE]         = eac_dispatch_create;
drv->MajorFunction[IRP_MJ_CLOSE]          = eac_dispatch_close;
drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = eac_dispatch_ioctl;
drv->DriverUnload                         = eac_unload;
```

---

## IOCTL dispatcher — where you'll live

```c
NTSTATUS eac_dispatch_ioctl(PDEVICE_OBJECT dev, PIRP irp)
{
    auto sp = IoGetCurrentIrpStackLocation(irp);
    ULONG raw = sp->Parameters.DeviceIoControl.IoControlCode;
    ULONG code = raw ^ g_dev->ioctlXorKey;

    if (!eac_is_authed(irp->FileObject)) {
        irp->IoStatus.Status = STATUS_ACCESS_DENIED;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_ACCESS_DENIED;
    }

    switch (code) { /* big switch — see IOCTL inventory below */ }
}
```

### The XOR key

32-bit, randomized at driver init, stored encrypted with the boot cookie in the device context. Lift live with a kernel debugger; statically it looks like another global. First time I reversed EAC I spent an afternoon wondering why IOCTL codes didn't match anything sensible until I caught the xor.

### Session auth at CREATE time

At first `CreateFile`, the client has to issue `IOCTL_EAC_SESSION_AUTH` with a blob containing:

- The launcher's cert chain
- A signed proof of `(pid, timestamp, nonce)`
- The game pid

Driver verifies the signature chain against a baked-in Epic public key, confirms the pid belongs to a process whose image was launched by an authenticated EAC launcher, and stamps the file object with a trust bit. Without that bit every other IOCTL short-circuits to `ACCESS_DENIED`. This is why you can open `\\.\EasyAntiCheat` from your own tool but can't do anything with it — you can't forge a session blob because the private key lives at Epic.

---

## Callbacks installed

Current builds install:

| Callback | API | Purpose |
|-|-|-|
| Process create | `PsSetCreateProcessNotifyRoutineEx2` (win11 23H2+) <br> or `…Ex` (fallback) | Classify every new process, flag known-bad loaders. Ex2 variant allows pre-creation veto. |
| Thread create | `PsSetCreateThreadNotifyRoutine` | Flag unusual thread start addresses in protected processes. |
| Image load | `PsSetLoadImageNotifyRoutine` | SHA256 every loaded DLL, match against rules.bin. |
| Handle open (proc) | `ObRegisterCallbacks(PsProcessType)` | **The strip.** |
| Handle open (thread) | `ObRegisterCallbacks(PsThreadType)` | Same, for thread handles. |
| Registry | `CmRegisterCallbackEx` | Watch tamper on EAC keys + CI + BCD. |
| ETW-TI | `EtwRegisterEx` (current only) | Subscribe to kernel-asserted suspicious events. |

### Process callback

Classifies by image path hash.

- **Game process** → tracked in protected-pid table.
- **Known-bad loader** → flagged.
- **With Ex2 veto flag set** → `CreationStatus = STATUS_ACCESS_DENIED`, creation fails. Used sparingly, only against high-severity blocklist entries.

The driver never kills a running process. Veto is pre-creation only.

### Thread callback

Reacts only on threads in a protected process. Reads `StartAddress` from `ETHREAD` (offset floats by Windows build — EAC has a dynamic resolver), classifies:

| Start address | Verdict |
|-|-|
| Known-good game module | ok |
| EAC's own modules | ok |
| `ntdll!LdrpInitializeThunk` | ok (normal creation path) |
| Non-whitelisted module | flag |
| Not in **any** LDR module | **flag hard** |

That last case is "a thread started in a VAD region with no backing module" — shellcode or a manually-mapped image. Both correlate hard with cheats.

### Image-load callback

Fires on every DLL load. Filters to protected processes. SHA256 first N pages. Matches against rules.bin's module section.

- Hash match → highest severity
- Path-suffix or byte-pattern match → medium
- Unsigned DLL under `system32` → own flag (unusual even outside cheats)

---

## The handle strip — `ObRegisterCallbacks`

The piece everyone writes about.

### Registration

```c
OB_CALLBACK_REGISTRATION reg = {
    .Version                     = OB_FLT_REGISTRATION_VERSION,
    .OperationRegistrationCount  = 2,
    .Altitude                    = { L"<rotating number>" },
    .RegistrationContext         = NULL,
    .OperationRegistration       = ops,
};

OB_OPERATION_REGISTRATION ops[2] = {
    { PsProcessType,
      OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
      eac_pre_proc_handle, NULL },
    { PsThreadType,
      OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
      eac_pre_thread_handle, NULL },
};
```

The altitude is a float-as-string. EAC picks a spot high enough to be above normal filesystem/AV filters, so EAC sees handle opens before any other callback could handle the IRP. Current builds moved higher than historical to avoid colliding with newer gamer-focused AV products.

### The pre-op callback

```c
OB_PREOP_CALLBACK_STATUS eac_pre_proc_handle(PVOID ctx,
                                              POB_PRE_OPERATION_INFORMATION op)
{
    if (op->KernelHandle)
        return OB_PREOP_SUCCESS;                      // kernel, skip

    HANDLE targetPid = PsGetProcessId((PEPROCESS)op->Object);
    if (!eac_is_protected(targetPid))
        return OB_PREOP_SUCCESS;

    HANDLE opener = PsGetCurrentProcessId();
    if (opener == targetPid)
        return OB_PREOP_SUCCESS;                      // self

    if (eac_is_trusted_opener(opener))
        return OB_PREOP_SUCCESS;

    ACCESS_MASK* mask = (op->Operation == OB_OPERATION_HANDLE_CREATE)
        ? &op->Parameters->CreateHandleInformation.DesiredAccess
        : &op->Parameters->DuplicateHandleInformation.DesiredAccess;

    *mask &= ~(PROCESS_VM_READ | PROCESS_VM_WRITE
             | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD
             | PROCESS_DUP_HANDLE | PROCESS_SET_INFORMATION
             | PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE);

    eac_telemetry_log(TEL_HANDLE_OPEN_ATTEMPT, opener);
    return OB_PREOP_SUCCESS;
}
```

### Non-obvious things about the strip

**1. It's in-place and total.** `OpenProcess` returns a handle that "works" but is neutered. `NtReadVirtualMemory` on it returns `ACCESS_DENIED`. This used to catch beginner cheat devs in 2018; everyone knows now.

**2. "Trusted opener" is authenticode cert-hash on the opener's image.** Renaming your tool to `EasyAntiCheat.exe` does not make it trusted. A surprising number of people have tried.

**3. The strip is not a block — it's a detection.** EAC logs every attempt with opener pid and command line. Your cheat just got reported even though the handle "succeeded."

### Thread strip mask

```c
THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME
| THREAD_TERMINATE | THREAD_DIRECT_IMPERSONATION
| THREAD_SET_INFORMATION | THREAD_SET_THREAD_TOKEN
```

Thread handle access matters because some cheats walk thread contexts to find TLS pointers.

---

## Registry callback

`CmRegisterCallbackEx` watches:

```
HKLM\SYSTEM\CurrentControlSet\Services\EasyAntiCheat         (self)
HKLM\SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS
HKLM\SYSTEM\CurrentControlSet\Control\CI                     (code integrity)
HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard
HKLM\SYSTEM\CurrentControlSet\Control\BootOptions
HKLM\SYSTEM\Setup                                            (safe-mode)
HKLM\BCD00000000                                             (BCD writes)
HKLM\SOFTWARE\Microsoft\Cryptography                         (MachineGuid)
```

Callback doesn't block — logs and flags. **BCD writes while Fortnite is live flag high severity** (that's where you'd toggle test-signing-mode).

---

## ETW-TI subscription (current-build addition)

Driver hooks into the `Microsoft-Windows-Threat-Intelligence` ETW provider — kernel-asserted suspicious events (process hollowing candidates, APC injection into system processes, etc.). EAC relays into its own telemetry. Needs `PsCreateSystemThread` + a worker consuming the ETW buffer. Exists on current, didn't exist historically.

---

## IOCTL inventory

Symbolic names mine; numbers rotate per version.

| IOCTL | Purpose |
|-|-|
| `SESSION_AUTH` | Handshake (covered above). |
| `READ_MEM` | Kernel-side read of target VA range. `polite` path = `MmCopyVirtualMemory`; `attach` path = `KeStackAttachProcess` + `ProbeForRead` + SEH. Flags select. |
| `WRITE_MEM_PROBE` | Reads one page, hashes, returns hash. Proves to backend that the game's `.text` at offset X still looks like Y. |
| `GET_MODULES` | LDR module list for a pid. |
| `GET_VAD` | **Full VAD tree walk.** The manual-mapped detector's ground truth. |
| `ENUM_HANDLES` | All open handles system-wide filtered to a target pid. Catches pre-callback-race handles + `LIMITED_INFORMATION` escalators. |
| `ENUM_THREADS` | Thread list + start addresses. |
| `PATTERN_SCAN` | Byte-pattern match against a VA range. Expensive, used sparingly. |
| `PROC_INFO` | PEB/TEB fields without touching user memory. |
| `DRIVER_LIST` | Loaded kernel drivers + hashes + signer cert thumbprints + **WDAC block-list match state** (current-build addition). |
| `CALLBACK_DUMP` | Enumerate `PsSet*` callback entries + Ob entries, hash owning driver each. |
| `PHYS_READ` | Physical-memory read via `MmMapIoSpace`. Still in classic current build; gone on EOS. |
| `SELF_CHECK` | Driver signs `(hash || nonce || bootCookie)` with embedded Ed25519 key. Agent forwards to backend. |
| `HEARTBEAT` | Keepalive. |
| `REPORT_FLAG` | Agent → driver: "I found this, add to session report." |

### READ_MEM structs

```c
struct eac_read_in  { HANDLE pid; PVOID va; SIZE_T size; ULONG flags; };
struct eac_read_out { NTSTATUS status; SIZE_T got; UCHAR data[]; };
```

Alignment paranoia matters. EAC's structs are packed in some places and not others. A misaligned field cost me three hours once because the agent and driver had slightly different packing on an older build.

---

## The VAD walker

This is how EAC catches manually-mapped cheats. The VAD (Virtual Address Descriptor) tree is Windows' record of every committed region of virtual memory in a process: every module, heap, `VirtualAlloc`. A manually-mapped DLL doesn't appear in `PEB->Ldr` (loaded outside `LoadLibrary`), but its allocation still shows as a VAD. The agent asks the driver for the VAD tree, compares against LDR, and anything executable in VAD but missing from LDR is suspect.

```c
NTSTATUS eac_walk_vad(PEPROCESS proc, OUT list)
{
    auto root = (PRTL_AVL_TABLE)((PUCHAR)proc + g_vadRootOffset);
    KeAcquireGuardedMutex(&proc->AddressCreationLock);
    for (auto vad = leftmost(root); vad; vad = inorder_next(vad)) {
        entry.base   = vad->StartingVpn << PAGE_SHIFT;
        entry.size   = (vad->EndingVpn - vad->StartingVpn + 1) << PAGE_SHIFT;
        entry.prot   = decode_protection(vad);
        entry.type   = decode_type(vad);               // Private/Mapped/Image
        if (entry.type == VadImageMap) {
            auto fo = get_file_object(vad);
            resolve_path(fo, entry.path);
        }
        append(list, entry);
    }
    KeReleaseGuardedMutex(&proc->AddressCreationLock);
    return STATUS_SUCCESS;
}
```

The `EPROCESS` `VadRoot` offset floats by Windows build. EAC resolves it dynamically — a small routine fingerprints the running kernel build at init and picks the offset from a table. Cheat devs who assumed EAC would be defeated by a new insider build "breaking" the offset learn the table exists.

---

## Scan worker — timer rotation

Runs on a 5-second loop, rotating through scans so no single tick is unboundedly expensive:

| `tick & 7` | Scan |
|-|-|
| 0 | VAD scan all protected processes |
| 1 | Thread enumeration |
| 2 | Handle enumeration |
| 3 | Module list diff vs previous |
| 4 | Self-integrity hash |
| 5 | Driver list scan |
| 6 | Callback-table dump |
| 7 | Cross-process hook heuristics |

Current builds added a second worker on a ~30s cadence doing an **environmental consistency pass**: pulls SMBIOS via WMI, compares to session-init cached values, flags drift. This is a spoof-detector hedge — a spoofer that only patches reads at init time but later system calls read the real values gets caught by drift.

---

## Self-anti-tamper

Driver verifies, periodically:

- Its own `.text` against a baked-in SHA256.
- That its callbacks are still registered (nobody unlinked the `PsSet*` entries).
- That the `ObCallbacks` table still contains its entry.
- That its device object is still present.

**Policy: DO NOT BSOD EVER if we can help it.** BSODing legit users because a weird-but-legal AV loaded in the wrong order would be a PR disaster. On self-hash mismatch the session is flagged at maximum severity. The ban eventually lands. The game does not crash.

---

**Next:** [03 — User-mode launcher](03-user-mode-launcher.md)
