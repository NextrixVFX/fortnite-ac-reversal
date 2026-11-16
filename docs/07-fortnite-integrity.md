# 07 — Fortnite's own integrity layer

This is a separate thing people conflate with EAC. The Fortnite shipping exe has anti-cheat logic that runs **independent** of EAC's DLL. Mostly wiring into UE5's anti-cheat module feature system, plus server-authoritative game logic.

Reversing this layer is worth it because:

- Many bans are delivered via Fortnite's own server checks, not EAC's scans.
- Understanding the client-server trust boundary tells you which "cheats" are visible vs invisible to EAC specifically.
- The EAC emulation PoC in [13](13-eac-emulation.md) needs to interact with this layer correctly.

---

## UE5 anti-cheat interface

Unreal has:

```cpp
class IOnlineAntiCheatCommon { ... };
class IAntiCheatModularFeature { ... };
```

Both abstract. EAC implements concretes. The integration lives in a UE module (`OnlineServicesEAC`, `OnlineAntiCheatEAC`, and friends — names vary per UE version). The game registers users (session attendees) via `RegisterUser`. All anti-cheat network traffic between client and server goes through:

```cpp
SendNetworkMessage(FUniqueNetIdRef, const uint8*, int32)
ReceiveNetworkMessage(FUniqueNetIdRef, const uint8*, int32)
```

on this interface. Which means **EAC's reports tunnel through Fortnite's own game netcode to reach Epic**. You can't block EAC telemetry at the network layer without also breaking matchmaking.

Clever design: EAC's reports reach Epic's infrastructure through a channel that already has to work for the game to function.

---

## Export-ordinal map (EAC_x64 ↔ Shipping)

The game calls `EasyAntiCheat_x64.dll` **by ordinal, not by name**. Ordinals rotate per EAC build.

Rough shape (names will match the EOS SDK public headers; ordinals are per-build):

| Ord | Name |
|-|-|
| 1 | `Client_Init` |
| 2 | `Client_Shutdown` |
| 3 | `Client_RegisterPeer` |
| 4 | `Client_UnregisterPeer` |
| 5 | `Client_ReceiveMessage` |
| 6 | `Client_PollStatus` |
| 7 | `Client_SetCallback` |
| 8 | `Client_GetProtectedData` |
| 9 | `Client_ReportBehavior` |
| 10 | `Client_AddNetworkToken` |
| 11 | `Client_RemoveNetworkToken` |

Plus a bunch more for session events, message signing, trust-state queries.

### Recovering the map

1. Dump `EAC_x64.dll` exports in CFF Explorer. Exports are by ordinal only; you get numbers.
2. Walk the game's IAT for its `EAC_x64.dll` imports.
3. The correspondence is **positional** — the game's Nth import is EAC's Nth export.
4. Name candidates come from UE5's public anti-cheat module source (in the engine) + the EOS SDK sample for anti-cheat integration (public).

---

## Server-authoritative checks (independent of EAC)

Each of these runs server-side. The client sends intent, the server validates reality. No matter how clean your EAC bypass is, these still catch you if your cheat affects observable game state.

### Movement authority

- Client sends movement intent (`UCharacterMovementComponent` input vector).
- Server simulates physics with authoritative inputs.
- Delta between server-sim and client-reported position checked against tolerance.
- Over-threshold → net correction (teleport you back) + counter increment.
- Sustained over-threshold → flag.

Catches: speed hacks, teleports, infinite jumps, no-clip.

Reverse via `ACharacter` / `APlayerCharacter` replication + the net-correction logic (`ServerMove` RPCs).

### Shot-rate validation

- Each weapon has a server-side minimum fire interval.
- Clients firing faster than that → extra shots discarded, counter incremented.
- Pattern of excessive overshoots → flag.

### Weapon spread validation

- Client cannot reduce spread below server config.
- Server computes **actual** projectile direction using its own spread cone.
- No-spread cheats get the client to display a tight shot but the projectile goes where the server decided.

### FOV validation

- FOV changers above the slider max → caught server-side.
- FOV is replicated for sanity; the server applies its own clamp.

### Build-placement validation

- Illegal placements (through walls, overlapping, through terrain) rejected server-side.
- Client's local build may show up for a frame, then disappear on reject.

### Resource delta validation

- Mats and ammo cross-checked.
- Impossible deltas (gaining mats without a harvest event) → flag.

None of this is EAC. This is Epic's own UE code. You find it in the shipping exe's reflection-tree under paths like `/Game/Athena/Items/…`, `/Script/FortniteGame`.

---

## Kick / soft-ban / hard-ban / HWID-ban taxonomy

Fortnite's enforcement tiers, from lightest to heaviest:

| Tier | What happens | Trigger |
|-|-|-|
| **Kick** | Session-only. No account consequence. | Typically client-side by EAC when the detection is immediate and unambiguous (overlay opened, kernel debugger attached). |
| **Soft ban** | Cooldown after match loss (minutes to hours). | Server heuristics. |
| **Shadow ban** | Matchmaking into a queue of flagged accounts. No notification. | Server correlation. **Epic's cleverest mechanism** — took the cheat community a long time to figure out it existed. |
| **Hard ban** | Account termination. | Server correlation across multiple sessions. |
| **HWID ban** | Hard ban plus hardware fingerprint block. | Repeat offender appears with a fresh account on same hardware. |

### Shadow ban mechanics

Specifically interesting because it's invisible. A shadow-banned account:

- Can still queue for matches.
- Only matches with other shadow-banned accounts (or sometimes bots).
- Doesn't earn competitive progress.
- Doesn't realize anything's wrong unless they play with a non-banned friend.

Server-side only. Nothing on the client distinguishes a shadow-matched session from a normal one.

### HWID ban binding

Covered in depth in [10 — cleaner & ban traces](10-cleaner-ban-traces.md), but the short version: the backend stores a hash over some combination of HWID fields (SMBIOS UUID, motherboard serial, disk serial, TPM EK hash, MAC prefix, machine GUID, …). On session start, agent collects, hashes, sends. Backend matches against ban list.

**Cleaning disk artifacts does not undo HWID bans.** HWID bans are hardware-rooted; the mitigation is spoofing (per [11](11-hwid-spoofing.md)) or new hardware.

---

## What's visible to EAC vs Fortnite's own checks

Useful mental model for understanding where a given cheat gets caught:

| Cheat type | Caught by | How |
|-|-|-|
| DLL injected into game | EAC agent | VAD scan, module scan, handle-open log |
| Kernel driver cheat | EAC driver | Driver list, callback dump, BYOVD matching |
| External memory reader (no injection) | EAC + behavior | Handle strip prevents reads; behavior caught by server checks |
| DMA cheat (external hardware) | Server checks only | EAC can't see it; input ML + behavioral correlation |
| Hypervisor-based cheat | EAC anti-VM | CPUID timing, APIC topology, hypervisor brand |
| Macros / recoil scripts | Server + input ML | Distributional analysis of mouse input |
| FOV changers | Server | Server clamps FOV |
| Server-side bot setup (second PC + capture card) | Server input ML only | Input anomaly + outlier win-rate correlation |

The pattern: EAC catches **client-process anomalies**. Fortnite catches **game-state anomalies**. External cheats evade EAC but can't evade game-state checks because the cheat has to affect game state to be useful.

---

**Next:** [08 — Protection stack](08-protection-stack.md)
