# 04 — User-mode agent (`EasyAntiCheat_x64.dll`, current)

Where most of EAC's intelligence lives. If your reversing time budget isn't weighted ≥70% here, you're budgeting wrong.

- The driver is maybe 8-10 KLOC of kernel C.
- The agent, unpacked, is probably 60-90 KLOC of user-mode C++, 30-40% of it inside VMProtect handlers you have to devirtualize before any of it reads meaningfully.

---

## Getting into a readable state

The on-disk DLL is VMProtect-packed with import protection. Workflow:

1. **Dump from memory** after full init inside the game.
2. **Scylla** the dump to rebuild the IAT from resolved pointers.
3. **NoVmp** the VMP regions.
4. **Hand-lift residual handlers** with unicorn-engine + VTIL.
5. **Label subsystems.**

Plan on a week minimum if you haven't done VMProtect devirt before. NoVmp covers 70-85% of handlers across most EAC builds; the rest you fingerprint one at a time.

Full protection-stack details in [08 — protection stack](08-protection-stack.md).

---

## DllMain + init chain

```c
BOOL DllMain(HINSTANCE h, DWORD why, LPVOID rsv)
{
    if (why == DLL_PROCESS_ATTACH) return eac_agent_init();
    if (why == DLL_PROCESS_DETACH) eac_agent_fini();
    return TRUE;
}

BOOL eac_agent_init(void)
{
    parse_cmdline_token_or_bail();
    verify_own_dll_integrity_or_bail();      // first self-check tick
    pipe_connect();
    pipe_hello();
    driver_session_auth();
    rules_load_and_decrypt();
    environment_sweep_once();                 // anti-vm, anti-debug,
                                              // initial module probe,
                                              // SMBIOS fingerprint cache
    spawn_worker_threads();
    install_game_hooks();
    return TRUE;
}
```

---

## Worker threads

| Thread | Cadence | Job |
|-|-|-|
| `scan_worker` | ~2s | Rotates module / window / thread / hook scans. |
| `pipe_worker` | blocking | Read incoming launcher messages, dispatch. |
| `telemetry_worker` | batched | Compress + encrypt + TLS to backend. |
| `integrity_worker` | ~2s (jittered) | Self + game module + system-DLL hashes. |
| `input_worker` | continuous | Mouse/keyboard hooks, distributional stats. |
| `capture_worker` | server-gated | DXGI OutputDuplication + Win32 `Graphics.Capture`. |
| `env_worker` | ~30s | **New.** Environmental drift check (SMBIOS, MAC, disk serial, machine GUID). |

---

## Pipe client

Wraps named-pipe I/O. After `HELLO` the payloads are **ChaCha20-Poly1305** under a session ephemeral key the launcher sends in `WELCOME` (upgraded from plain ChaCha20 in historical builds — current uses the AEAD mode).

See [05 — pipe protocol](05-pipe-protocol.md) for frame format and opcode list.

---

## Driver client

Thin wrapper over `DeviceIoControl` with the XOR quirk from the kernel side:

```c
NTSTATUS drv_call(ULONG code, void* in, ULONG inl, void* out, ULONG outl)
{
    ULONG real = code ^ g_sessionCookie;
    DWORD got = 0;
    if (!DeviceIoControl(g_drv, real, in, inl, out, outl, &got, NULL))
        return GetLastError() | 0xC0000000;
    return 0;
}
```

Per-IOCTL wrappers sit above this. The `g_sessionCookie` XOR is the user-mode side of the kernel's `ioctlXorKey`; they're derived from the same session negotiation at auth time.

---

## Rules engine

Loads `pbrules.bin` at init, decrypts, parses sections. See [06 — rules.bin](06-rules-bin.md) for the file format.

Runtime matching lives behind functions roughly shaped like:

```c
BOOL eac_rules_match_module(const wchar_t* path, const uchar hash[32]);
BOOL eac_rules_match_process(const wchar_t* exe);
BOOL eac_rules_match_window(const wchar_t* className);
BOOL eac_rules_match_driver(const UCHAR hash[32]);
BOOL eac_rules_match_signer(const UCHAR certThumb[32]);  // current
BOOL eac_rules_match_smbios(int kind, const char* value); // current
```

Each dispatches into the appropriate rule section, iterates entries, checks match-mode (hash / path-suffix / pattern / signer / SMBIOS-field), returns the severity tag.

---

## Scanners

The part most writeups are hazy on because there are a lot of them.

### Module scanner

Runs on timer, also fires on every image-load notification piped from the driver.

- Calls `GET_MODULES` for the game process. Walks LDR. Matches each entry against rules.bin module sections. Hash match → high severity. Path-suffix or pattern → medium.
- Calls `GET_VAD`. Builds a set of every executable VAD region. For each, checks whether an LDR entry covers that range. If not and the region is executable, flag.
  - `VadImageMap` without LDR → "unlinked image."
  - `VadPrivate` with executable protection → "shellcode region."
- **Transient-executable detector (current-build):** two VAD snapshots two seconds apart. Any region that was R/W in the first and R/X in the second (flipped while we weren't looking) is flagged — classic "flip executable to run, flip back" cheat pattern.
- **Entropy check:** walk executable VADs, compute Shannon entropy on a 64KB sample. Real x86 code sits around 6.0-6.5 bits/byte. Packed or encrypted code runs 7.5+. Over threshold → flag. Catches unpacking stubs mid-flight.

### Window scanner

The overlay / ESP detector.

- `EnumWindows` callback grabs classname and title for every top-level window.
- Matches against rules.bin window sections. Known cheat UI classes flagged on sight.
- **Transparent-topmost windows over the game's client rect get flagged** even if the class isn't known — the pattern itself is suspicious.
- Legit overlays (Discord, NVIDIA, Steam) have their properties on an internal baked-in whitelist (not in rules.bin — baked into the DLL for freshness).
- **Current-build addition:** windows with no owner but rendering via d3d11/d3d12 directly get flagged. Real applications typically go through a user32 window for input routing; renderless D3D windows are unusual outside overlays.

### Thread scanner

- `NtQuerySystemInformation(SystemProcessInformation)`, filter to own pid, iterate threads.
- Classify start addresses the same way the driver's thread callback does.
- User-mode cross-check in case the driver's callback path got subverted. Belt and suspenders.

### Hook detector

Periodically loads a clean copy of important system DLLs and diffs `.text` pages against in-memory.

Modules checked (current build):

```
ntdll.dll, kernel32.dll, kernelbase.dll, user32.dll, win32u.dll,
d3d11.dll, d3d12.dll, dxgi.dll, gdi32.dll, gdi32full.dll
```

Historical approach was to load the "clean copy" from `\KnownDlls`. Current builds bundle their own known-good baselines (section hashes + raw bytes for the first ~16 KB of `.text` of each module). The change is in response to cheats modifying the `\KnownDlls` section objects before the agent could consult them. Bundled baselines are updated per Windows version via telemetry.

**Export-pointer check (current).** Several key exports (`NtOpenProcess`, `NtReadVirtualMemory`, `LdrLoadDll`, `NtCreateFile`, …) are resolved at agent init and cached. Periodically re-resolved; mismatch flags "export rebound."

### DXGI frame capture

Gated by server-side config.

- Reference `d3d11` device, `OutputDuplication` object on monitor 0.
- Every N seconds, composited frame captured.
- **Current-build also uses `Graphics.Capture` API on win11 as a fallback** — desktop duplication misses some overlay compositions and `Graphics.Capture` sees things it doesn't.
- Frames are JPEG-compressed (or AVIF on current, smaller payload). Shipped via telemetry.
- Backend runs vision models looking for aim circles, bounding boxes, crosshair overlays that the window scanner would never see (overlays drawn directly into the game's swapchain or via DWM composition).

### Input anomaly detector

- Hooks `WH_MOUSE_LL` + RawInput.
- Tracks dX/dY per tick, sub-pixel step distributions, device ID consistency, time-to-shot latencies after a snap.
- Agent doesn't make ban decisions — bins data, ships summaries. Backend ML models score the distributions.
- **Current-build addition:** tracks the kernel-level mouse driver chain (walks `\Driver\MouseClass`'s device stack via a user-mode heuristic plus the driver's helper). Cheats using kmbox-like hardware or custom mouse drivers show an unusual driver chain. Rolls up into the "mouse-driver block list" section of rules.bin.

### Integrity timer

- Self `.text` + each game module's `.text` + **current-build expansion to system DLLs** (`ntdll`, `kernelbase`, `win32u`).
- Expected hashes baked into rules.bin or delivered in session init.
- Mismatch → max severity.
- Interval is short (every 2s) and **jittered** within a window to defeat scheduling by cheats that hook briefly between ticks.

---

## TLS transport + pin check

Statically-linked TLS stack. Current builds use a BoringSSL fork. Trusts a small set of certificate SPKI hashes hardcoded in the DLL.

```c
int eac_tls_verify_cert(cert_chain)
{
    compute SPKI SHA256 of leaf → spkiHash;
    for (int i = 0; i < EAC_PIN_COUNT; i++)
        if (!memcmp(spkiHash, g_pinHashes[i], 32)) return 1;
    return 0;
}
```

**To mitm for research:** find the pin function (string xref "pin" or xref from TLS handshake code), patch `memcmp` → `mov al, 1; ret`. Install your CA, mitmproxy sees cleartext.

---

## Telemetry packet format

Framed binary, protobuf-ish but not. Current builds use zstd compression with a shared dictionary baked into the agent DLL (look for an ~8 KB blob referenced near the telemetry init).

```
header:
  u16 version
  u16 flags
  u32 bodyLen
  u8  msgType
  u8  severity
  u16 reserved

body: zstd-dict(Fields)
  u16 tag
  u16 len
  u8  value[len]
```

### Current-build tag list

| Tag | Content |
|-|-|
| `0x0001` | Session id (16 byte GUID) |
| `0x0002` | Timestamp u64 ms since epoch |
| `0x0010` | Flag id u32 |
| `0x0011` | Severity u8 |
| `0x0012` | Flag-specific data |
| `0x0020` | Module info (path + hash + base + size + authenticode signer thumbprint) |
| `0x0021` | VAD info (base + size + protection + type + backing file path) |
| `0x0022` | Thread info (tid + start_addr + state) |
| `0x0030` | CPUID dump (leaves 1, 7, `0x8000000{1,2,3,4}`, `0x40000000`) |
| `0x0040` | Window info (hwnd + class + title + rect + style flags + `has_d3d_swapchain`) |
| `0x0050` | Driver info (name + hash + size + signer + WDAC blocklist state) |
| `0x0060` | Screenshot bytes (image format tag + compressed payload) |
| `0x0070` | Input stats block |
| `0x0080` | Environmental fingerprint (SMBIOS + disk hash + MAC hashes + GPU LUID + machine GUID + TPM EK hash + Windows product id) |
| `0x0090` | Driver chain for mouse/keyboard (ordered names + hashes) |
| `0x00A0` | Kernel callback dump (addr + owning driver hash) |

### Severity

| Level | Meaning |
|-|-|
| 0 | Info |
| 1 | Warning |
| 2 | Suspicious |
| 3 | Fatal (flagged for ban) |

### Flag-ID groupings

| Prefix | Family |
|-|-|
| `0x10xx` | Module / VAD / shellcode / injection |
| `0x11xx` | Thread family |
| `0x12xx` | Handle / API access |
| `0x13xx` | Window / overlay |
| `0x14xx` | Hook / integrity |
| `0x15xx` | Driver / signing |
| `0x16xx` | Process / parent |
| `0x17xx` | Debugger |
| `0x18xx` | VM / hypervisor |
| `0x19xx` | Registry / BCD |
| `0x1Axx` | Input anomaly |
| `0x1Bxx` | Frame-capture overlay |
| `0x1Cxx` | **Environmental fingerprint (new in current)** |
| `0x1Dxx` | **Server-pushed auxiliary scanner findings (new)** |

### Ban timing

Getting a fatal flag does not mean instant ban. Flag gets logged server-side, correlated across sessions. Current-build correlation cadence is daily (used to be weekly), with hard-correlated flag chains triggering near-realtime bans within hours.

Still: "my cheat worked for a week before I got banned" is a normal story.

---

## Backend endpoints

Current build:

- `api.epicgames.dev` — session reports (both classic and EOS).
- `modules-cdn.eac-prod.on.epicgames.com` — auxiliary scanner module downloads.

Legacy (resolve but 410 for new sessions):

- `service.easyanticheat.net`
- `api.easy.ac`

---

**Next:** [05 — Pipe protocol](05-pipe-protocol.md)
