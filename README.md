# fortnite-ac-reversal

Deep reverse-engineering notes on Fortnite's full anti-cheat stack: Easy Anti-Cheat (classic + EOS variant), Fortnite's own integrity layer, the surrounding HWID / fingerprint surface, trust-score mechanics, ETW-TI hazards, and three real-world emulator architectures analyzed in detail. Includes an EAC emulation PoC + the raw-offset reversal of a current-build driver.

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

### Deep-dive technical reversal

| | Doc | What's in it |
|-|-|-|
| 15 | [Driver raw offsets](docs/15-driver-raw-offsets.md) | **The current `EasyAntiCheat_EOS.sys` reversed at the byte level.** Hash constants, the "cage", flattened dispatcher, 46-module manifest, HWID formatter, trust-score plumbing. RVA-by-RVA. |
| 16 | [Telemetry endpoints](docs/16-telemetry-endpoints.md) | Exact URLs, headers, event catalog, body format, named kernel objects, MITM method. |
| 17 | [Trust-score model & feature flags](docs/17-trust-score-model.md) | How EAC decides what runs on your machine. The per-handler feature-flag bit system. Operational signals for pre-ban-wave detection. |
| 18 | [ETW-TI & kernel hazards](docs/18-etw-ti-and-kernel-hazards.md) | What Microsoft-Windows-Threat-Intelligence sees, PatchGuard, HVCI, DMA Protection, WDAC. The specific constraints a spoofer/cheat driver has to operate under. |

### Focused sections

| | Section | What's in it |
|-|-|-|
| A | [Cleaner & ban traces](docs/10-cleaner-ban-traces.md) | Every on-disk trace EAC + Windows leaves. Every live-queried HWID field. Comprehensive cleaner inventory. Why cleaning alone doesn't beat HWID bans. |
| B | [HWID spoofing surface](docs/11-hwid-spoofing.md) | Per-field spoofer mechanics — SMBIOS (incl. history), disk serial, MAC, CPU, GPU, EDID, TPM, Windows identity. Full spoofer architecture. |
| C | [Cheat detection surface](docs/12-cheat-detection.md) | What EAC flags: kernel drivers (BYOVD), injection indicators, hooking patterns, external/hardware cheats (DMA, kmbox, capture-card), signature patterns. |
| D | [EAC emulation + PoC](docs/13-eac-emulation.md) | Conceptual emulator architecture, limits, working PoC (code in [`poc/eac-emu-stub/`](poc/eac-emu-stub/)). |

### Real-world artifact analysis

Three different emulator / bypass architectures, analyzed from actual binaries + source:

| | Doc | What |
|-|-|-|
| — | [Analysis index](docs/analysis/00-index.md) | Overview of the three approaches |
| 01 | [desire_market full EAC-EOS emulator](docs/analysis/01-desire-market-emulator.md) | Self-provisioned EOS product + bundled HWID spoof driver. Not a Fortnite bypass — a toolkit for building your own EAC-protected product. Includes full `spoof.sys` HWID-surface analysis. |
| 02 | [UC Linux-proxy emulator](docs/analysis/02-uc-linux-proxy-emulator.md) | Windows → Linux EOS/EAC proxy. Full dual-side source. Exploits that Linux-under-Proton EAC is weaker than Windows EAC. |
| 03 | [MCC in-process bypass](docs/analysis/03-mcc-in-process-bypass.md) | Runtime RVA-patch on EOS integrity check + XUID spoof. User-mode only. Works for MCC because it doesn't ship EAC's kernel driver stack. |

### Workflow

| Doc | What's in it |
|-|-|
| [Workflow & verification checklist](docs/14-workflow-and-checklist.md) | Day-by-day reversal plan, environment setup, correctness checklist. |

### Code

- [`poc/eac-emu-stub/`](poc/eac-emu-stub/) — compilable stub `EasyAntiCheat_x64.dll` that satisfies a game's EAC integration without running checks. Useful for offline / private-server / modding work. **Does not bypass live-server session signing.**

### Raw originals

- [`original/fortnite_anticheat_reversal.txt`](original/fortnite_anticheat_reversal.txt) — the recon/roadmap doc in plain text.
- [`original/fortnite_anticheat_reversed_internals.txt`](original/fortnite_anticheat_reversed_internals.txt) — the full teardown as a single plain text file.

---

## How to read this repo

- **New to EAC reversing:** [00 current-build notes](docs/00-current-build-notes.md) → [14 workflow](docs/14-workflow-and-checklist.md) → architecture docs 02 → 09 in order.
- **Want the deepest byte-level reversal:** [15 driver raw offsets](docs/15-driver-raw-offsets.md) is the current public state of the art, with real offsets you can verify against your own IDA session.
- **Investigating a ban / planning a clean:** [A cleaner & ban traces](docs/10-cleaner-ban-traces.md). For the HWID binding specifically, [B HWID spoofing](docs/11-hwid-spoofing.md) and [18 ETW-TI hazards](docs/18-etw-ti-and-kernel-hazards.md).
- **Writing / understanding cheats:** [C cheat detection](docs/12-cheat-detection.md) is the map. For how trust decisions get fed, [17 trust-score model](docs/17-trust-score-model.md). For what network events to watch for pre-ban signals, [16 telemetry endpoints](docs/16-telemetry-endpoints.md).
- **Building EAC emulation:** [D EAC emulation](docs/13-eac-emulation.md) for the architecture, [`poc/eac-emu-stub/`](poc/eac-emu-stub/) for the code, and the three [analysis](docs/analysis/00-index.md) docs for real-world precedent.
- **Whole thing in one plain-text file:** [`original/fortnite_anticheat_reversed_internals.txt`](original/fortnite_anticheat_reversed_internals.txt).

---

## What's in here that's "different"

Most public EAC writeups cover the surface mechanics — what callbacks it registers, what it scans, how handle stripping works. This repo pushes further into:

- **Byte-level reversal** with real RVAs and hash constants for the current driver build ([15](docs/15-driver-raw-offsets.md)). Where the "cage" lives. The splitmix64 hash dispatch constant (`0x9E3779B185EBCA87` — 1071 sites). The 46-module manifest with per-tag meanings.
- **The feature-flag mechanism** ([17](docs/17-trust-score-model.md)). Every detection handler has a bit the backend can flip per-session. "I bypassed check X" doesn't matter when the backend rotates to check Y.
- **The exact telemetry endpoints and event catalog** ([16](docs/16-telemetry-endpoints.md)). `api.epicgames.dev/telemetry/data/datarouter/api/v1/public/data`. User-Agent `Easy Anti-Cheat EOS/1.0.0`. Event names: `AntiCheat.Error.GameTrust`, `AntiCheat.Error.IntegrityViolation`, `AntiCheat.Error.Theia` (unknown subsystem).
- **The Kaspersky SSL MITM trick** for getting cleartext out of EAC's pinned telemetry stream ([16](docs/16-telemetry-endpoints.md)).
- **SMBIOS history tracking** ([15.5](docs/15-driver-raw-offsets.md#section-155--hwid-formatter-0x914b2--0x92e78)). The driver remembers SMBIOS values across sessions. Spoofers that rotate values get flagged on drift even when individual sessions look fine.
- **ETW-TI as the specific mechanism** that constrains spoofers ([18](docs/18-etw-ti-and-kernel-hazards.md)). The `shm PATCH_PTE refused (EAC TI ProtectVm)` error string from a real shipping spoofer confirms the mechanism in the wild.
- **Three real-world emulator architectures** compared and analyzed from actual binaries + source ([analysis](docs/analysis/00-index.md)).

---

## Confidence tiers

Through the docs, claims fall into tiers. The source docs tagged these explicitly; the markdown split keeps the same voice but lets context carry most of it:

- **Verified by public RE** (Secret Club, published teardowns, this repo's own analysis of shipping artifacts, Microsoft-documented behavior) — correct at the architectural + behavioral level; constants rotate.
- **Reconstructed from behavior** — observed via live tracing, pipe captures, driver probing. Correct at "what it does"; specific instruction sequences will differ per build.
- **Inferred** — strong educated hypothesis from adjacent facts. Treat as a starting hypothesis for your own IDA session.

Verify everything against your own pulled binaries before baking into tooling. The [verification checklist](docs/14-workflow-and-checklist.md#verification-checklist) is the list of specific values you must lift locally.

---

## Not in scope here

- **Help getting unbanned.** Nothing in here is an exploit or a way to beat server-side correlation. The emulation PoC explicitly does not bypass live-server session signing.
- **Current-build cheat code.** This document covers the *detection surface*. It does not ship cheats.
- **Binaries.** Pull them yourself from your own Fortnite install — this repo contains analysis, not Epic's binaries.

---

## Ack

Standing on a lot of public work:

- [Secret Club](https://secret.club/) — repeated EAC teardowns over the years.
- [can1357 / NoVmp](https://github.com/can1357/NoVmp) — VMProtect devirtualizer that makes current EAC tractable.
- [VTIL-Core](https://github.com/vtil-project/VTIL-Core) — the IL NoVmp emits.
- [Mellow's blog](https://mellow.bio/) — EAC specifics.
- [hasherezade / pe-sieve](https://github.com/hasherezade/pe-sieve) — the tool you want running next to any live-reverse session.
- [wbenny / HyperDbg](https://github.com/wbenny/HyperDbg) — hypervisor-level debugger for anti-cheats that defeat Dr0..Dr3 in user mode.
- UnknownCheats teardown threads whose authors mostly go by handle-only — the deep-reversal in [15](docs/15-driver-raw-offsets.md) is one of these, consolidated here.
- `mrdhanz` / `@ShimadaNanaki` — UC EAC/EOS Linux-proxy emulator (analyzed in [analysis/02](docs/analysis/02-uc-linux-proxy-emulator.md)).

---

_Research notes. No license. Use responsibly — treat the repo as "notes a researcher might dump to a friend," not a how-to guide._
