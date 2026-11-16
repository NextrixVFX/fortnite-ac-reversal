# fortnite-ac-reversal

Reverse-engineering notes on Fortnite's full anti-cheat stack: Easy Anti-Cheat (classic + EOS variant), Fortnite's own integrity layer, the surrounding HWID / fingerprint surface, and an EAC emulation PoC. Compiled from a lot of years of IDA sessions and a running pile of public prior art (Secret Club, Mellow, can1357, the UC teardown threads).

Current-build era: **late-2026** (EAC agent `EAC_2026_*`, Fortnite UE5).

> **Read before trusting any specific constant:** this is a map of the *architecture*. Offsets inside `EPROCESS`, altitude strings, XOR keys, AES salts, numeric IOCTL codes, pin hashes, and flag IDs rotate every few builds. Always re-derive constants against your own pulled binaries.

---

## Contents

### Architecture teardown

| | Doc | What's in it |
|-|-|-|
| 00 | [Current-build notes](docs/00-current-build-notes.md) | What's new vs historical. Read first. |
| 01 | [On-disk inventory](docs/01-on-disk-inventory.md) | Every file that ships, every path. |
| 02 | [Kernel driver](docs/02-kernel-driver.md) | `EasyAntiCheat.sys` — callbacks, IOCTLs, VAD walker, self-protect. |
| 03 | [User-mode launcher](docs/03-user-mode-launcher.md) | `EasyAntiCheat.exe` — spawn + inject + pipe. |
| 04 | [User-mode agent](docs/04-user-mode-agent.md) | `EasyAntiCheat_x64.dll` — all the scanners live here. |
| 05 | [Pipe protocol](docs/05-pipe-protocol.md) | Frame format, opcodes, handshake. |
| 06 | [rules.bin](docs/06-rules-bin.md) | File format, key derivation, section types. |
| 07 | [Fortnite integrity layer](docs/07-fortnite-integrity.md) | UE5 side — IAntiCheat binding, server-authoritative checks. |
| 08 | [Protection stack](docs/08-protection-stack.md) | VMProtect, custom VM, CFG flattening, anti-debug, anti-VM, anti-dump, IAT. |
| 09 | [EOS variant delta](docs/09-eos-variant.md) | What's different in `EasyAntiCheat_EOS.*`. |

### Focused sections

| | Section | What's in it |
|-|-|-|
| A | [Cleaner & ban traces](docs/10-cleaner-ban-traces.md) | Every on-disk trace EAC + Windows leaves, every live-queried HWID field, comprehensive cleaner inventory, why cleaning alone doesn't beat HWID bans. |
| B | [HWID spoofing surface](docs/11-hwid-spoofing.md) | Per-field spoofer mechanics — SMBIOS, disk serial, MAC, CPU, GPU, EDID, TPM, Windows identity. Full spoofer architecture. |
| C | [Cheat detection surface](docs/12-cheat-detection.md) | What EAC flags: kernel drivers (BYOVD), injection indicators, hooking patterns, external/hardware cheats (DMA, kmbox, capture-card), signature patterns. |
| D | [EAC emulation + PoC](docs/13-eac-emulation.md) | Conceptual emulator architecture, limits, working PoC (code in [`poc/eac-emu-stub/`](poc/eac-emu-stub/)). |

### Workflow

| Doc | What's in it |
|-|-|
| [Workflow & verification checklist](docs/14-workflow-and-checklist.md) | Day-by-day reversal plan, environment setup, correctness checklist. |

### Code

- [`poc/eac-emu-stub/`](poc/eac-emu-stub/) — compilable stub `EasyAntiCheat_x64.dll` that satisfies a game's EAC integration without running checks. Useful for offline / private-server / modding work. **Does not bypass live-server session signing.**

### Raw originals

- [`original/fortnite_anticheat_reversal.txt`](original/fortnite_anticheat_reversal.txt) — the recon/roadmap doc in plain text.
- [`original/fortnite_anticheat_reversed_internals.txt`](original/fortnite_anticheat_reversed_internals.txt) — the full teardown as a single plain text file. Everything above is split out of this.

---

## How to read this repo

- If you're **new to EAC reversing**: start with [00 current-build notes](docs/00-current-build-notes.md), then [14 workflow](docs/14-workflow-and-checklist.md) for the plan, then work the architecture docs 02 → 08 in order.
- If you're **investigating a ban**: go straight to [A cleaner & ban traces](docs/10-cleaner-ban-traces.md). For HWID binding, [B HWID spoofing](docs/11-hwid-spoofing.md).
- If you're **writing / defending against cheats**: [C cheat detection](docs/12-cheat-detection.md) is the map of EAC's detection surface.
- If you want **EAC emulation**: [D EAC emulation](docs/13-eac-emulation.md) for the architecture, [`poc/eac-emu-stub/`](poc/eac-emu-stub/) for the code.
- If you want the **whole thing in one file**: [`original/fortnite_anticheat_reversed_internals.txt`](original/fortnite_anticheat_reversed_internals.txt).

---

## Confidence tiers

Through the docs, claims fall into tiers. The source doc tagged these explicitly; the markdown split keeps the same voice but lets context carry most of it. When in doubt:

- **Verified by public RE** (Secret Club, published teardowns, Microsoft-documented behavior) — correct at the architectural + behavioral level; constants rotate.
- **Reconstructed from behavior** — observed via live tracing, pipe captures, driver probing. Correct at "what it does"; specific instruction sequences will differ per build.
- **Inferred** — strong educated hypothesis from adjacent facts. Treat as a starting hypothesis for your own IDA session.

Verify everything against your own pulled binaries before baking into tooling. The [verification checklist](docs/14-workflow-and-checklist.md#verification-checklist) is the list of specific values you must lift locally.

---

## Not in scope here

- **Help getting unbanned.** Nothing in here is an exploit or a way to beat server-side correlation. The emulation PoC explicitly does not bypass live-server session signing.
- **Current-build cheat code.** This document covers the *detection surface*. It does not ship cheats.
- **Pulled binaries.** Pull them yourself from your own Fortnite install — this repo contains analysis, not binaries.

---

## Ack

Standing on the shoulders of a lot of public work:

- [Secret Club](https://secret.club/) — repeated EAC teardowns over the years, the "how anti-cheats detect system emulation" series in particular.
- [can1357 / NoVmp](https://github.com/can1357/NoVmp) — VMProtect devirtualizer that makes current EAC tractable.
- [VTIL-Core](https://github.com/vtil-project/VTIL-Core) — the IL NoVmp emits.
- [Mellow's blog](https://mellow.bio/) — EAC specifics.
- [hasherezade / pe-sieve](https://github.com/hasherezade/pe-sieve) — the tool you want running next to any live-reverse session.
- [wbenny / HyperDbg](https://github.com/wbenny/HyperDbg) — hypervisor-level debugger for anti-cheats that defeat Dr0..Dr3 in user mode.
- Countless UnknownCheats teardown threads whose authors mostly go by handle-only.

---

_Research notes. No license. Use responsibly — treat the repo as "notes a researcher might dump to a friend," not a how-to guide._
