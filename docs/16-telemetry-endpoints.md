# 16 — Telemetry endpoints, event catalog, and the MITM method

The exact outbound surface from `EasyAntiCheat_EOS.exe` to Epic's backend, with file offsets, headers, event names, and a working MITM approach.

---

## Service → Epic transport

The service reports to Epic over **plain HTTPS POST**. Stack: libcurl + schannel + Negotiate strings are present. Proxy resolution via `WinHttpOpen` / `WinHttpGetIEProxyConfigForCurrentUser` / `WinHttpGetProxyForUrl` (file offsets `0xBB105 – 0xBB208`).

### Primary endpoint

```
POST https://api.epicgames.dev/telemetry/data/datarouter/api/v1/public/data
  ?AppVersion=1.0.0
  &AppEnvironment=Production
  &UploadType=sdkevents
  &AppID=EOSSDK.AntiCheatExt.Service
  &SessionId=<...>
```

Stored at file offset `0xAFC2C`.

### Secondary / legacy endpoint

```
POST https://datarouter.ol.epicgames.com/datarouter/api/v1/public/data
  ?AppVersion=1.0.0
  &AppEnvironment=Production
  &UploadType=eteventstream
  &AppID=easyanticheat
  &SessionId=<...>
```

Stored at file offset `0xAFCE0`.

### Headers

| Header | Value | File offset |
|-|-|-|
| `Content-Type` | `application/json` | `0xAFDEE` / `0xAFDFF` |
| `User-Agent` | `Easy Anti-Cheat EOS/1.0.0` | `0xAFE0C` / `0xAFE26` |
| `Service` | `1.5.9` | `0xAFD85` |

---

## Body format

Not a generic JSON serializer. Built by concatenating fixed string fragments in a specific order (key order included):

```
{"Events":[              (0xAFBA8)
{"EventName":"           (0xAFBB4)
","Source":"             (0xAFBC3)
","BuildTime":"          (0xAFBCE)
","ProductId":"          (0xAFBDC)
","SandboxId":"          (0xAFBEA)
","DeploymentId":"       (0xAFBF8)
","OSName":"             (0xAFC09)
","OSVer":"              (0xAFC14)
","BuildId":             (0xAFC1E)    <- numeric, no closing quote
```

### Field sources

- `ProductId` = the EOS `ProductId`.
- `OSName` / `OSVer` / `BuildId` = Windows `CurrentVersion` registry keys (lookup near `0xB0A08`).
- `SandboxId` / `DeploymentId` = per-title EOS identifiers.

---

## The event catalog (`0xAFE31 – 0xB00FE`)

Every event name the service may emit. **Reading this catalog is the fastest way to understand what EAC actually flags.**

```
AntiCheat.Generic.TestValue

AntiCheat.Error.Bugcheck
AntiCheat.Error.BugcheckDetailed
AntiCheat.Error.GameTrust                    <- the one that correlates to bans
AntiCheat.Error.GameApplicationError
AntiCheat.Error.IntegrityViolation           <- the other one that correlates
AntiCheat.Error.GameHardError
AntiCheat.Error.Launch
AntiCheat.Error.ValidateError
AntiCheat.Error.ServiceUpdateFailed
AntiCheat.Error.GameException
AntiCheat.Error.NetworkProtocol
AntiCheat.Error.Theia                        <- unknown subsystem
AntiCheat.Error.Undefined

AntiCheat.Warning.ChunkFailure
AntiCheat.Warning.GameTerminationAbnormal
AntiCheat.Warning.AbnormalShutdown
AntiCheat.Warning.BadOSVersion

AntiCheat.Info.DriverInitResult
AntiCheat.Info.DriverInitTime
AntiCheat.Info.DriverUnloadDuration
AntiCheat.Info.SandboxInfo
AntiCheat.Info.SandboxEventInfoFile
AntiCheat.Info.SandboxProcess
```

### Field groupings

- **`GameTrust`** / **`IntegrityViolation`** / **`ValidateError`** → the enforcement-correlated events. These are the ones you want to see *absent* from your traffic.
- **`Theia`** → unknown subsystem. The researcher who dumped this couldn't confirm what Theia is.
- **`DriverInitResult`** / **`DriverInitTime`** / **`DriverUnloadDuration`** → routine telemetry, baseline-expected.
- **`BadOSVersion`** / **`ChunkFailure`** → environment anomalies.
- **`SandboxInfo`** / **`SandboxProcess`** → per-session environment facts.

---

## Named kernel objects + service-registry state

For logging without touching the kernel, EAC leaves behind:

### Named events

```
Global\EasyAntiCheat_EOSEventDriver    (exe 0xBC762)
Global\EasyAntiCheat_EOSEventGame      (exe 0xBD236)
Global\EasyAntiCheat_EOSEventModule    (exe 0xBD27A)
```

These are standard Windows named events (`CreateEventW` / `OpenEventW`). Subscribing to them reveals the driver / game / module heartbeat without any hooking.

### Registry state keys

Under `SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS\`:

```
Attestation                           (exe 0xB0C00, 0xB0EF2)
ProductsInstalled                     (exe 0xB0E50)
ErrRpt_GameCrashExitStatus            (exe 0xBC694)
ErrRpt_LastUnloadDuration             (exe 0xBC858)
ErrRpt_GameState                      (exe 0xBD104)
ErrRpt_ServiceState                   (exe 0xBD126)
ErrRpt_GameCrashExitTime              (exe 0xBD15A)
ErrRpt_LastInitTime                   (exe 0xBD18C)
ErrRpt_GameCrashCreateTime            (exe 0xBD1B4)
ErrRpt_LastInitSandboxId              (exe 0xBD300)
ErrRpt_LastInitDeploymentId           (exe 0xBD332)
```

These are accessible with any registry viewer. They reflect the service's last session state and error flags. **Useful for ban-trace cleanup (`ErrRpt_*` values survive game-level uninstall).**

---

## Driver ↔ service frame protocol

Lives at the very beginning of `.text` (`0x1000 – 0x1200`) and in a couple of RAW gap functions.

### Byte-order split

Envelopes are **little-endian dwords**. Payload values inside are **big-endian**. Watch this.

### Container init (`0x1020 – 0x1099`)

- Magic dwords: `{1, 2, 1, 0x6C}` — built on the stack at runtime; **you won't find it raw in the file**.
- Min size: `0x50`.
- Data starts at `ctx+0x50`.
- Cap = `size - 0x50`.
- State byte at `+0x40`.
- Flags at `+0x44` (low nibble = op class).
- List head at `+0x48`.

### Push wrapper: `0x1150 – 0x11FA`

### Big-endian value accessors

```
0x53A0  read u8
0x53F0  read u16 BE (rol ax, 8)
0x54A0  write u32 BE (bswap)
0x54F0  read u32 BE (bswap)
```

### Envelope writer (RAW gap, no unwind): `0x24F360 – 0x24F3AF`

```
writes:  [dst+0x00] = type       (1..5, or 0)
         [dst+0x04] = class      (>= 2, or == 2 when type == 0)
         [dst+0x08] = 0x378      (fixed marker, 888)
error:   0x80100004 on invalid args
success: returns 0x100000
```

### Error space

```
Container:    0x80004, 0x80005, 0x80007, 0x80012, 0x80016
Marshalling:  0x90005 (null), 0x90006 (truncation)
```

### Observed pushed message size

`0x17A` bytes.

---

## MITM method — the Kaspersky trick

The service does **cert pinning**. Standard mitmproxy gets ignored.

**But** — Kaspersky's "SSL protection" package installs its own CA as *trusted on the machine*. You can:

1. Install Kaspersky with SSL protection enabled (or extract the CA from an existing install).
2. Export Kaspersky's CA cert + private key.
3. Use that CA as the signing CA for mitmproxy.
4. The service accepts certs signed by that CA (because it's in the trust store Kaspersky put it in).
5. mitmproxy sees cleartext.

Combined with:

- The **named events** (`Global\EasyAntiCheat_EOSEvent*`) for driver/game/module heartbeat signals.
- The **`ErrRpt_*` registry state** for post-session state inspection.
- **Named-pipe tapping** inside the game process for the agent ↔ launcher pipe (see [05 — pipe protocol](05-pipe-protocol.md)).

you get the **full outbound picture without touching the kernel at all.**

---

## What you capture per session

Running the above setup against one Fortnite session gives you:

| Source | Captures |
|-|-|
| mitmproxy on datarouter endpoint | Every event name + event body + session id |
| Pipe tap in-process | Agent ↔ launcher heartbeats, flag reports, module list, VAD list, driver list |
| Named-event subscriber | Driver init / game init / module load timing |
| Registry snapshot | ErrRpt state, Attestation state |

Running the same across N sessions on the same machine gives you the **per-handler feature-flag rotation** (see [15.2.e](15-driver-raw-offsets.md#152e--flattening--selector--kill-switches)) — because the backend is deciding which handlers fire each session, and you can watch the flag bitmap change.

---

## Signal: pre-ban activity

Direct observation: **rising `IntegrityViolation` / `GameTrust` event frequency is the pre-wave signal.**

Normal baseline is `DriverInitResult` + `DriverInitTime` + a few `SandboxInfo` per session. If you start seeing `IntegrityViolation` or multiple `GameTrust` per session, your HWID / driver / network has likely been flagged and the backend is collecting correlation data for an imminent ban.

Weeks-to-months window typically; **minimum ~1 week for new drivers.** Once fully detected and after collection phase, **ban is instant.**

---

**Next:** [17 — Trust-score model & feature flags](17-trust-score-model.md)
