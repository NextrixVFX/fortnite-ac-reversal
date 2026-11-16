# 09 — EOS variant delta

`EasyAntiCheat_EOS.*` is architecturally similar to classic EAC — if you've reversed classic, reversing EOS is maybe 30% additional work for the deltas. This doc is the diff.

---

## What changed

### Driver

`EasyAntiCheat_EOS.sys` is smaller — maybe 55% the on-disk size of classic. Several IOCTLs moved to user mode or were removed entirely.

| IOCTL | Classic | EOS |
|-|-|-|
| `SESSION_AUTH` | ✓ | ✓ |
| `READ_MEM` | ✓ (polite + attach paths) | ✓ (polite only) |
| `WRITE_MEM_PROBE` | ✓ | ✓ |
| `GET_MODULES` | ✓ | ✓ |
| `GET_VAD` | ✓ | ✓ |
| `ENUM_HANDLES` | ✓ | ✓ |
| `ENUM_THREADS` | ✓ | ✓ |
| `PATTERN_SCAN` | ✓ | **moved to user mode** |
| `PROC_INFO` | ✓ | ✓ |
| `DRIVER_LIST` | ✓ | ✓ |
| `CALLBACK_DUMP` | ✓ | **moved to user mode** (via `NtQuerySystemInformation(SystemBigPoolInformation)` + pool-tag pattern matching) |
| `PHYS_READ` | ✓ | **removed** |
| `SELF_CHECK` | ✓ | ✓ |
| `HEARTBEAT` | ✓ | ✓ |
| `REPORT_FLAG` | ✓ | ✓ |

### Why `PHYS_READ` got dropped

WDAC and attestation pressure on newer Windows made `MmMapIoSpace` calls more flaggable (and WHQL submission harder), so Epic decided user-mode checks with VAD walking cover most of the same use cases. The classic driver still has it because enough older EAC-protected games depend on it.

### No persistent service

- Classic: `EasyAntiCheat` is a persistent `SERVICE_DEMAND_START` service.
- EOS: driver loads on demand when a protected game launches, unloads on exit. No persistent service entry.

Means you can't `sc query EasyAntiCheat_EOS` to see if it's "installed." The driver only exists on disk — loading happens as part of game launch.

### Symbolic link + device name

- Classic: `\\DosDevices\\EasyAntiCheat` → `\\Device\\EasyAntiCheat_<random>`
- EOS: `\\DosDevices\\EasyAntiCheatEOS` → `\\Device\\EasyAntiCheatEOS_<random>`

### ObCallbacks altitude

Different number. Picked to not collide with classic EAC (so both can be loaded simultaneously for games that integrate both).

### Pipe name

- Classic: `\\.\pipe\EasyAntiCheat_<session>`
- EOS: `\\.\pipe\EOS_EAC_<session>`

---

## Transport

Through the EOS SDK.

- **Endpoint:** `api.epicgames.dev`
- **Pin set:** pulled from EOS SDK data section at session init, rather than baked into `EasyAntiCheat_EOS_x64.dll` directly.
- **No legacy `easyanticheat.net` endpoints.**

This matters because the pin check code path is different — the EOS variant locates pin hashes at runtime via EOS SDK internals, so static-finding the pin table requires different xref anchors than classic. The pin-patching technique is the same (`memcmp` → `mov al, 1; ret`), but the location differs.

---

## What stayed the same

For completeness, so you know where to re-use your classic reversing:

- All kernel callbacks + semantics (`PsSetCreateProcessNotifyRoutineEx`, thread, image, `ObRegisterCallbacks`, `CmRegisterCallbackEx`).
- Handle-strip mechanism + strip masks.
- VAD walker approach (same `EPROCESS` offsets, same lock acquisition).
- Module / VAD diff logic.
- Rules engine file format (same `pbrules.bin` layout).
- Window scanner / overlay detection.
- Hook detector (with the same bundled baseline approach).
- Integrity timer + jittered interval.

---

## Things specific to EOS SDK integration

### EOS SDK handle propagation

EOS Anti-Cheat Client is exposed through:

```c
EOS_HAntiCheatClient EOS_Platform_GetAntiCheatClientInterface(EOS_HPlatform);
```

Classic EAC has its own C API that doesn't go through this handle pattern. If the game integrates via EOS SDK, the exports exposed by `EasyAntiCheat_EOS_x64.dll` match the public EOS AntiCheat Client interface signatures — the PoC in [13](13-eac-emulation.md) targets this interface.

### Trust level

EOS has an `AntiCheatTrustLevel` concept exposed via:

```c
EOS_EResult EOS_AntiCheatClient_SetReceiveMessageCallback(
    EOS_HAntiCheatClient, const EOS_AntiCheatClient_AddNotifyMessageToPeerOptions*,
    ...);
```

Peers in a session carry a trust level the local EAC assigns (based on its judgments of them) and that server policy can act on. Reversing the trust propagation is part of understanding why "I got shadow-banned for joining a lobby with a cheater" happens — trust is transitive in some configs.

---

## Running EOS variant in a research VM

Same cautions as classic (see [14 — workflow](14-workflow-and-checklist.md)) but with one addition: because the EOS driver loads on-demand only during game launch, you can't pre-stop it with `sc stop EasyAntiCheat_EOS`. If you want to examine the driver at rest, copy the `.sys` from `FortniteGame\Binaries\Win64\EasyAntiCheat_EOS\` before the game ever launches. Once Fortnite launches the EOS variant, it loads the driver; on game exit the driver unloads but the file on disk may have been swapped if EAC's auto-update ran.

---

**Next:** [10 — Cleaner & ban traces](10-cleaner-ban-traces.md)
