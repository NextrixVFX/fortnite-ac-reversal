# D — EAC emulation

What emulating EAC means, why you'd do it (offline / private-server / mod-platform use cases), and a working PoC of a stub EAC client that satisfies a game's integration contract without running anti-cheat checks.

**Code lives in [`poc/eac-emu-stub/`](../poc/eac-emu-stub/).** This doc is the explainer.

---

## What "emulating EAC" means

Two possible halves:

| Half | What it is |
|-|-|
| **(1) Client-side stub** | A replacement `EasyAntiCheat_x64.dll` with the same export table, same ordinals, same function signatures as real EAC. All exported functions return "success" or no-op values. |
| **(2) Backend emulator** | A stand-in for Epic's EAC backend. Talks the EAC backend protocol over EOS SDK, issues valid-looking session signatures using keys the emulator controls, which the game's local EAC client accepts. |

The PoC in this repo is **(1) only**. (2) is private-server territory — the server side signs tokens the client verifies, so you need corresponding pubkeys on the client side. The mechanics mirror (1), inverted.

---

## What (1) alone gets you

**Can:**

- Let a game that integrates EAC start up and run its own code path without EAC blocking it.
- Enable:
  - Offline single-player / sandbox / creative modes that don't require matchmaking.
  - Private-server implementations (OG emulations like the older seasons of Fortnite on private servers).
  - Research / modding work.
  - UE5 integration debugging without touching EAC's live telemetry.

**Cannot:**

- Play against Epic's live Fortnite servers. The backend verifies session signatures from a private key EAC holds, not in the client. A stubbed client gets kicked at matchmaking time.

---

## Stub DLL architecture

- **Match the real `EAC_x64`'s export table ordinal-by-ordinal.** The game imports by ordinal, so ordinal 5 in your stub must be whatever ordinal 5 means in the real EAC (`Client_Init`, whatever). If the game calls your stub expecting `Client_RegisterPeer` but your stub's ordinal N is `Client_PollStatus`, the game crashes or malfunctions.
- **Each stubbed function takes the same parameters as the real one** and returns a value the game will interpret as "fine, move on." For status-returning functions, that's typically `EOS_EResult::EOS_Success` (value 0) or equivalent.
- **Callback-registering functions** (`Client_SetCallback` and family) store the callback pointer and periodically call it with "nothing bad detected" results.

### Ordinal recovery

The actual EAC exports from the EOS SDK's anti-cheat client interface are publicly documented at the EOS developer docs. Classic EAC exports are a superset of those on top of the EOS base — the additional exports cover features like protected network messages, trust-level queries, multi-peer session handling.

To match a target Fortnite build:

1. Open the real `EasyAntiCheat_x64.dll` in CFF Explorer.
2. Dump the export table — it's by ordinal only.
3. Open the Fortnite shipping exe's IAT for its `EAC_x64.dll` imports.
4. Positional mapping — game's Nth import is EAC's Nth export.
5. Name candidates come from UE5's public anti-cheat module source + EOS SDK public samples.
6. Update your stub's `.def` to match.

---

## The PoC — what's in [`poc/eac-emu-stub/`](../poc/eac-emu-stub/)

- [`eac_emu_stub.c`](../poc/eac-emu-stub/eac_emu_stub.c) — single C file implementing the stub. ~200 lines.
- [`eac_emu_stub.def`](../poc/eac-emu-stub/eac_emu_stub.def) — module definition file assigning ordinals.
- [`build.bat`](../poc/eac-emu-stub/build.bat) — MSVC build script.
- [`README.md`](../poc/eac-emu-stub/README.md) — PoC-specific notes.

### Build

Open a Developer Command Prompt for VS, run:

```bat
cd poc\eac-emu-stub
build.bat
```

Or manually:

```bat
cl /LD /O2 eac_emu_stub.c /Fe:EasyAntiCheat_x64.dll ^
   /link /DEF:eac_emu_stub.def
```

Output: `EasyAntiCheat_x64.dll` + a `.lib` and `.exp`.

### Use

1. Rename the real `EasyAntiCheat_x64.dll` in your Fortnite install to `EasyAntiCheat_x64.dll.bak`.
2. Drop the stub in its place.
3. Launch via `FortniteClient-Win64-Shipping.exe` directly — **not** the `_EAC` wrapper, which runs integrity checks on EAC itself.
4. The game's IAT resolves against your stub, the stub returns success, the game proceeds as if EAC said OK.

---

## Limits of this approach

### Server-side rejection

Epic's backend doesn't accept sessions without a valid EAC backend session signature. A stubbed client gets kicked at matchmaking time. The stub is **ONLY useful for:**

- Offline single-player / sandbox / creative modes that don't require matchmaking
- Private-server implementations where you control both ends
- Research / modding where EAC integration otherwise prevents loading

### Launcher wrapper refuses the stub

`FortniteClient-Win64-Shipping_EAC.exe` loads `EasyAntiCheat.exe` first, which verifies the on-disk hash of `EAC_x64.dll` **before** injection. Your stub has a different hash, the launcher refuses.

**Bypass:** Launch the base `FortniteClient-Win64-Shipping.exe` directly, which doesn't do this check. The game's own argv-parsing recognizes it's been launched outside the EAC wrapper and either exits (newer builds outright exit) or silently runs in a degraded mode (older builds).

### Current-build signature check breaks the stub on live Fortnite

Current builds (2026) have added an in-game check: the shipping exe verifies that EAC's init callback has returned not just success but also a matching **Ed25519 signature over session state** that only the real EAC can produce.

A stub's callback return won't carry that signature → current Fortnite will **exit at startup** even when launched directly.

### Workarounds for current-build shipping exe check

The private-server community has handled this a few ways:

- **Patch the shipping exe to skip the EAC init signature check.** Find the verification function via string xrefs like `"anti-cheat init failed"` or similar, replace the compare/branch with a `jmp`. Ships with the exit-at-startup check fully neutralized.
- **Implement real backend emulation with your own signing key.** Replace the pinned Epic pubkey in the shipping exe (or in `EAC_x64`) with yours. Your emulated backend signs sessions with the matching private key. The stub propagates these signatures. Full private-server path.

---

## Full private-server stack

For running a private Fortnite server (e.g. Fortnite OG emulation), the complete picture:

| Component | What it does |
|-|-|
| **(a) Stub `EasyAntiCheat_x64.dll`** (or patched shipping exe skipping EAC init signature check) | Makes the client not block on EAC |
| **(b) Private server** | Implements Fortnite's game protocol |
| **(c) Backend emulation** | Stands in for Epic's matchmaking, leaderboards, and critically the EAC backend session-signing |
| **(d) Patched shipping exe** | Accepts your emulated backend's signature (replace pinned pubkey in shipping exe or `EAC_x64` with yours) |

Community-maintained projects doing this openly (Project Reboot and similar efforts) have implemented all four. Detailed implementation is out of scope for this doc — the shape above is the roadmap.

---

## Historical analogies

Nothing novel in the architecture. The specific implementation against current Fortnite is just more work than against older games because current-build EAC verifies signatures the stub can't produce.

- **EmuWarface** — Warface private servers.
- **Various EAC-less private servers** for games that have gone offline.
- **UDK-era Unreal games with EAC stubs** for modding.

Each follows the same pattern: stub client + emulated backend + patched game binary where needed.

---

## What this PoC does NOT do

Being explicit about scope:

- **Does not bypass live-server session signing.** Can't be used to play on Epic's servers.
- **Does not disable EAC's driver.** The kernel driver still loads if the service is running. The stub operates at the DLL layer.
- **Does not provide any cheat capability.** Just makes the game not depend on EAC's integration contract. Cheating still requires separate work and is not in scope here.
- **Does not include the private-server backend.** Just the client-side half.

Purely research / modding / private-server scaffolding.

---

**Next:** [Workflow & verification checklist](14-workflow-and-checklist.md)
