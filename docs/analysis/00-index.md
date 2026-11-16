# Analysis — three real-world EAC bypass / emulation artifacts

Three different approaches to defeating EAC, each analyzed from actual binaries + source. Each represents a distinct architecture.

| | Approach | Scope | Required capability |
|-|-|-|-|
| [01](01-desire-market-emulator.md) | **Full EAC-EOS launcher emulation** with bundled HWID spoof driver | Launch a game under a self-provisioned "EAC" session that reaches real Epic backend with controlled credentials | Kernel driver + real EOS product provisioning |
| [02](02-uc-linux-proxy-emulator.md) | **Windows → Linux EOS/EAC proxy** | Offload EAC/EOS session to Wine/Proton where integrity checks are weaker | Dual-side DLL hook (Windows client + Linux server over WebSocket) |
| [03](03-mcc-in-process-bypass.md) | **In-process EOS integrity-check patch + identity spoof** for Halo MCC | NOP the specific EOS validation function + overwrite local XUID with host XUID | User-mode DLL injection, specific RVA knowledge |

Each is covered in its own doc. This index page orients between them.

---

## Core architectures contrasted

### Full emulation ([01 desire_market](01-desire-market-emulator.md))

- Ships **its own `FortniteLauncher.exe`, its own `start_protected_game.exe`, its own `eacemu_emu.dll`.**
- Provisions **its own EOS product** (real `product_id`, real `sandbox_id`, real `client_secret` in `eos.json`).
- Includes a **`spoof.sys` HWID spoof driver**.
- Replaces the `EasyAntiCheat` directory via a bundled `eac_pack.zip`.
- Target: run a locally-built "protected game" that the real EOS backend will acknowledge as a session, because the product and credentials are legitimate (just not Fortnite's).

Not a Fortnite bypass. **It's a toolkit to build your own EAC-protected game using EAC's infrastructure.**

### Linux proxy ([02 UC emulator](02-uc-linux-proxy-emulator.md))

- Windows side: replacement `EOSSDK-Win64-Shipping.dll` that **proxies every EOS SDK call over WebSocket / HTTP** to a Linux backend.
- Linux side: `version.dll` loaded via `WINEDLLOVERRIDES` into a Proton prefix where the real EOS SDK + EAC Linux client run.
- The real Linux EOS/EAC client talks to Epic's backend. Session is legitimate from Epic's view.
- **Exploits that EAC's Linux-under-Proton integrity checks are weaker** than the full Windows kernel integration.

Works for games that can tolerate running their session under Wine/Proton on the Linux side while the user plays on Windows. Specific to EOS-integrated titles.

### In-process RVA patch ([03 MCC bypass](03-mcc-in-process-bypass.md))

- Runtime user-mode DLL injected into a running game.
- NOPs a **specific EOS SDK function** at hard-coded RVA (`0x3AD910` → `ret; nop*4`) to short-circuit the EOS integrity validation inside `EOSSDK-Win64-Shipping.dll`.
- Spoofs **XUIDs**: reads the host's XUID from MCC's session object, writes it over the local XUID in the title DLL (Halo Reach / 3 / ODST / 4 / H2A).
- Backs up original bytes, restores on process detach.

The simplest and most fragile of the three — requires per-build RVA knowledge, works for only one game (MCC), and depends on the specific EOS validation routine being short-circuitable with a RET.

---

## What each tells you

### desire_market tells you

**EAC is provisionable.** Epic sells EAC as a service through the EOS developer portal. Any dev can provision an EAC-protected product with their own credentials. The emulator uses this: it registers its own "eacemu" product, gets real credentials, and uses them to mint real EAC sessions. The "spoof" part (the bundled driver) is for *protecting* that product's test games against external cheat tools, but structurally everything else is above-board.

Implication for Fortnite: you can't use desire_market to play Fortnite — Fortnite's product_id / sandbox_id are Epic's, and you don't have Epic's client_secret. But the architecture shows that **the EAC protocol is well-documented when you're inside the SDK**. The emulator didn't reverse the protocol — it uses the official SDK against infrastructure it owns.

### UC emulator tells you

**EAC on Linux/Proton is weaker than on Windows.** The Linux variant of EAC exists (for Steam Deck + Proton compatibility) but it runs in a Wine environment without real Windows kernel callbacks. The user-mode integrity checks can be subverted. The "trick" is: let the Linux EAC client do its (weak) integrity checks on the Linux side where you control the environment, let it talk to Epic's backend and get a valid session, then relay session state back to the Windows game client via WebSocket.

Implication for Fortnite: **doesn't work for Fortnite specifically.** Fortnite doesn't have a Linux build, so there's no Linux EAC session to proxy to. But works for Unity-based EOS titles that do have Linux Proton support (VRChat, SpiritVale, others listed in the UC thread).

### MCC bypass tells you

**EOS integrity validation is a user-mode function in `EOSSDK-Win64-Shipping.dll` that can be short-circuited with a RET.** Specific to EOS SDK (not EAC-protected titles that use the full EAC kernel driver stack). MCC uses EOS for matchmaking but doesn't have EAC's kernel driver component, which is why the bypass works.

Implication for Fortnite: doesn't apply — Fortnite ships EAC's full kernel driver stack, not just the EOS SDK. The equivalent function in current Fortnite EAC would be the Ed25519 signature check on EAC init (per [13 — EAC emulation](../13-eac-emulation.md)), which has to not just return "success" but produce a cryptographically-valid signature.

---

## What none of these do

- **None play on live Fortnite servers.** Each either (a) runs against a controlled backend, (b) proxies through weaker Linux EAC, or (c) targets a game with weaker integrity (MCC via EOS without kernel EAC).
- **None defeat current-build Fortnite's Ed25519 signature check on EAC init.**
- **None spoof Fortnite's HWID binding to the backend ban list.**

The pattern: **full Fortnite live-server bypass requires Epic's private keys**, which nobody has. What the real projects do is either run a parallel infrastructure (Project Reboot style private servers) or target games where the client's own integrity check can be short-circuited (MCC).

---

**Next:** [01 — desire_market full emulator analysis](01-desire-market-emulator.md)
