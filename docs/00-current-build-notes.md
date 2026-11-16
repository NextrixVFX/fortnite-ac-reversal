# 00 — Current-build notes

> **What this doc is:** a changelog from historical EAC (2018-2023 era) to what's shipping on current Fortnite builds (late-2026, agent version strings around `EAC_2026_*`). Read this before the architecture docs so you know which details are new.

---

## The headline changes

### Kernel driver

- **Expanded BYOVD matching.** `DRIVER_LIST` used to return name + hash. It now also returns image size, signer cert thumbprint, and the Microsoft WDAC vulnerable-driver block-list state (whether the driver matches a block-list entry). Renaming your vulnerable driver buys you nothing — image hash is what matters, and signer revocation flags you even with a valid-looking cert.
- **`PsSetCreateProcessNotifyRoutineEx2` on win11 23H2+.** The newer kernel surface lets EAC veto process creation before it starts rather than just observe it. The veto path is used sparingly — EAC still prefers "observe and report" — but known-bad loaders get stopped early.
- **ObRegisterCallbacks altitude moved.** Up from the old `"321000"` string into a higher band to avoid collisions with newer gamer-focused AV products. The specific number this build is one you lift live.

### Crypto

- **rules.bin moved from AES-128-CBC to AES-256-GCM.** Key derivation is still HKDF-SHA256 but with a longer output and a different `info` string.
- **Signature outside the ciphertext changed from RSA-PSS to Ed25519.** Smaller sig (64 bytes vs 256), same guarantee, faster verify.

### Scanners

- **Dual frame-capture path.** DXGI OutputDuplication plus Win32 `Graphics.Capture` on win11. Desktop duplication can be defeated in some multi-monitor edge cases; `Graphics.Capture` sees things it doesn't.
- **Integrity hash set expanded.** Current builds hash `ntdll.dll`, `kernelbase.dll`, `win32u.dll`, and `dxgi`/`d3d11` stubs on top of the game's modules. A user-mode hook on any of those system DLLs gets caught by a single tick of the integrity worker.
- **Hook-detector baselines moved on-DLL.** From `\KnownDlls` (which could be tampered with before the agent consulted it) to bundled known-good pages shipping with the agent. Bundled baselines can't be modified at runtime without triggering self-integrity.
- **New `env_worker` thread.** Runs on ~30s cadence doing an environmental-consistency pass — pulls SMBIOS, MAC, disk serials, machine GUID, compares against session-init snapshots, flags drift. This is a spoof-detector hedge: if your spoofer only patches reads at init time but later system calls read the real values, EAC catches the drift.
- **ETW-TI integration.** Driver subscribes to the `Microsoft-Windows-Threat-Intelligence` ETW provider for kernel-asserted suspicious events (process hollowing candidates, APC injection into system processes, etc.) and relays them into EAC's own telemetry.

### Telemetry

- **All transport consolidated to `api.epicgames.dev`.** Both classic and EOS. The legacy `service.easyanticheat.net` endpoints resolve but return 410 for new sessions. If you see traffic there, your build is stale.
- **AEAD on the pipe.** Chacha20-Poly1305 replaced plain Chacha20. Per-frame 12-byte nonce + 16-byte tag.
- **Compression with a baked dictionary.** Telemetry body is zstd with a shared dictionary (~8 KB) baked into the agent DLL.
- **New flag family `0x1Cxx` — environmental fingerprint anomalies.** Things like a BIOS vendor string the backend has never seen, or a TPM endorsement key the backend has never issued a session for. Informational, not immediately ban-worthy, but drives ML correlation.
- **Daily correlation cadence.** Ban waves still exist but the correlation cadence shortened from weekly to daily. Some high-severity flag chains trigger near-realtime bans (hours not days).

### Remote scanner loading

- **`REMOTE_MODULE_LOAD` pipe opcode.** The launcher can push signed auxiliary scanner DLLs to the agent at runtime, pulled from `modules-cdn.eac-prod.on.epicgames.com`. Epic deploys new detections without shipping a new EAC version. The module is Ed25519-signed by Epic, manually mapped (never `LoadLibrary`'d), given a minimal IAT, and called with an EAC-provided scan context.

### Fortnite-side

- **UE5-current integration.** Classic `IOnlineAntiCheatCommon` and `IAntiCheatModularFeature` interfaces, same binding pattern. Ordinals rotate per EAC build.
- **Shipping exe signature-check on EAC init callback.** Current builds verify not just that EAC's init returned success but also that the init callback carried an Ed25519 signature over session state that only the real EAC can produce. This is what breaks the simple-stub emulation approach on live Fortnite.

---

## What's unchanged

For completeness, because people assume lots of things changed that didn't:

- **Callback APIs.** `PsSetCreateProcessNotifyRoutineEx` (or Ex2), `PsSetCreateThreadNotifyRoutine`, `PsSetLoadImageNotifyRoutine`, `ObRegisterCallbacks`, `CmRegisterCallbackEx`. Same surface, same semantics.
- **Handle strip mechanism.** Same `ObRegisterCallbacks` pre-op pattern, same strip mask for process (`PROCESS_VM_READ | PROCESS_VM_WRITE | …`), same for thread (`THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | …`).
- **VAD walker approach.** Still the gold standard for catching manually-mapped modules. Still uses `KeAcquireGuardedMutex(&proc->AddressCreationLock)` and an in-order walk.
- **Caller authentication model.** User-mode agent still has to present a signed session blob to the driver at CREATE time to be trusted.
- **VMProtect 3.x as primary obfuscator.** Ultra-mutation + import protection enabled, selected functions virtualized, rest is plain native code.
- **No BSOD policy.** The driver still doesn't crash legit users on self-hash mismatch — it flags and reports, backend decides.

---

## What's gone

- **BattlEye.** Dropped around 2021. If you're auditing a pre-2022 ban wave, see section 9 in the [original single-file doc](../original/fortnite_anticheat_reversed_internals.txt) for BattlEye notes.
- **Legacy `easyanticheat.net` transport.** DNS still resolves, HTTP 410 on new sessions.
- **AES-128-CBC rules.bin.** Replaced by AES-256-GCM.
- **RSA-PSS rules.bin signature.** Replaced by Ed25519.
- **Trusting `\KnownDlls` for hook-detector baselines.** Bundled baselines now.

---

## Version-triage quick tips

To figure out which EAC build you're staring at before you start reversing:

- **`SplashScreen.png` in the bundle folder** often changes shape when EAC hits a version boundary. Not reliable alone but useful for rough dating.
- **Agent build string in telemetry packets** (`EAC_2026_MM_DD` pattern). Lift from a pipe capture.
- **Signer cert thumbprint on `.sys` + `.dll`.** `signtool verify /pa /v`. Thumbprints and sign dates narrow down the window.
- **IOCTL dispatcher size.** Current-build driver dispatcher is bigger than historical (new IOCTLs added, see [`02 kernel driver`](02-kernel-driver.md)).
- **Imports tab in IDA on the `.sys`.** 5-ish imports → current (name-resolution). 50+ imports → pre-2019.

---

**Next:** [01 — On-disk inventory](01-on-disk-inventory.md)
