# 05 — Pipe protocol

Named pipe between `EasyAntiCheat.exe` (server) and the injected `EasyAntiCheat_x64.dll` (client).

- Path: `\\.\pipe\EasyAntiCheat_<session-guid>`
- Mode: `PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE`
- Flags: `PIPE_REJECT_REMOTE_CLIENTS`
- Overlapped I/O both sides.

---

## Frame format

```
'EACP'       u32  magic
opcode       u16
flags        u16  (bitfield — see below)
payloadLen   u32
crc32        u32  (of payload)
payload      u8[payloadLen]
```

### Flags

| Bit | Meaning |
|-|-|
| `0x1` | `ENCRYPTED` — payload is ChaCha20-Poly1305 under session ephemeral key. |
| `0x2` | `ACK_REQUIRED` — sender expects an ack frame. |
| `0x4` | `FRAGMENT` — payload continues in next frame. |

### Encryption (when `ENCRYPTED` is set)

- Cipher: **ChaCha20-Poly1305** (upgraded from plain ChaCha20 historically).
- Nonce: 12 bytes = `[session_nonce_prefix (8)] + [counter (4)]`. Counter increments per frame.
- Tag: 16-byte Poly1305 tag appended after the ciphertext.
- Key: 32-byte session ephemeral key, delivered by the launcher in `WELCOME`.

---

## Handshake

First few frames are unencrypted so both sides can agree on the session key.

### 1. `HELLO` (agent → launcher)

```
protocolVer   u16
agentBuild    char[32]      // "EAC_2026_MM_DD" style
processId     u32
bootCookie    u64
```

### 2. `WELCOME` (launcher → agent)

```
sessionId        u8[16]       // GUID
ephemeralKey     u8[32]       // ChaCha20-Poly1305 key
serverTime       u64
```

From here on frames can set `ENCRYPTED`.

### 3. `AUTH` (agent → launcher)

```
sessionToken     u8[...]      // the launcher's signed proof-of-launch blob
```

### 4. `AUTH_OK` or `AUTH_FAIL` (launcher → agent)

```
AUTH_OK:
  capsBitmap     u32          // which features the launcher's build supports

AUTH_FAIL:
  reasonCode     u32
```

### 5. `CONFIG` (launcher → agent)

```
scan_intervals {
  module_s, window_s, hook_s, integrity_s, input_s     // all u16
}
enabled_modules          u64       // bitmap of which scanners are on
frame_capture_period_s   u16
env_check_period_s       u16
```

### 6. (optional) `REMOTE_MODULE_LOAD` (launcher → agent)

Carries a signed auxiliary scanner DLL. Agent verifies the Ed25519 signature with an Epic pubkey, manually maps the module, calls its entrypoint with an EAC-provided scan context. Module stays resident for the session.

---

## Opcode table

Numbers rotate per build — descriptions by behavior.

### Agent → launcher

| Opcode | Content |
|-|-|
| `HELLO` | Build id, protocol version, pid. |
| `AUTH` | Session token blob. |
| `HEARTBEAT` | Periodic keepalive. |
| `REPORT_FLAG` | A scan found something. |
| `REPORT_MODULE_LIST` | Periodic LDR snapshot. |
| `REPORT_VAD` | Periodic VAD snapshot. |
| `REPORT_DRIVERS` | Periodic kernel driver list. |
| `REPORT_CALLBACKS` | Competing kernel callbacks. |
| `REPORT_SCREENSHOT` | Compressed captured frame (JPEG or AVIF). |
| `REPORT_INPUT_STATS` | Binned mouse distributions. |
| `REPORT_ENV_DRIFT` | Environment-fingerprint change observed. **(New in current.)** |
| `PIPE_LOG` | Debug log. Usually debug builds only. |
| `BAIL` | Fatal, closing connection. |

### Launcher → agent

| Opcode | Content |
|-|-|
| `WELCOME` | Session id, ephemeral key, server time. |
| `AUTH_OK` / `AUTH_FAIL` | Response to agent `AUTH`. |
| `CONFIG` | Scan intervals + enabled module bitmap. |
| `RULES_UPDATE` | Push a refreshed rules blob. |
| `REQUEST_SCAN` | Immediate scan of category N. |
| `REQUEST_SCREENSHOT` | Capture a frame now. |
| `KICK` | Please close gracefully. |
| `HARD_KILL` | Die now. |
| `REMOTE_MODULE_LOAD` | Load a signed auxiliary scanner DLL from the module CDN. **(New in current.)** |

---

## `REMOTE_MODULE_LOAD` deep dive

The interesting current-build opcode.

### Why

Lets Epic deploy new detections without shipping a new EAC version. A new cheat loader appears in the wild; Epic reverses it, writes a scanner, signs it, pushes it. Next session start, every player's agent pulls the new scanner down, runs it alongside the baked-in ones.

### How

1. Launcher receives (or has cached) a signed module blob from `modules-cdn.eac-prod.on.epicgames.com`.
2. Launcher pushes it to the agent over the pipe via `REMOTE_MODULE_LOAD`.
3. Agent verifies the Ed25519 signature with a baked-in Epic pubkey.
4. Agent **manually maps** the module (not `LoadLibrary` — adding an unsigned-path-looking module to LDR would be hygiene-breakage and self-flag).
5. Agent builds a minimal IAT via `GetProcAddress` internally.
6. Agent calls the module's exported entrypoint with a pointer to an EAC-provided `scan context`.
7. The scan module reports findings back via a callback in the context.
8. Module stays resident for the session, unmapped at teardown.

### How to capture

Two routes:

- **Pipe tap.** Dump pipe frames from inside the game process. When you see a `REMOTE_MODULE_LOAD` frame, the payload is the raw signed DLL bytes.
- **CDN tap.** mitmproxy on `modules-cdn.eac-prod.on.epicgames.com` after patching EAC's pin check per [08 — protection stack](08-protection-stack.md).

Capture every remote module every session. They accumulate — new detections get added, old ones get retired. Build a corpus; each module is a mini-RE project on its own.

---

**Next:** [06 — rules.bin](06-rules-bin.md)
