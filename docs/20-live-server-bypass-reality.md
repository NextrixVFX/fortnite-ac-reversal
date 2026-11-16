# 20 — Live-server bypass: what's actually required, what's been tried, what works

The gap the PoC in [13 EAC emulation](13-eac-emulation.md) doesn't close. This chapter is "why" — what makes Fortnite's live-server authentication cryptographically hard to forge, which attacks theoretically close it, and what real projects have actually achieved.

---

## Part 1 — What "live-server bypass" actually requires

Fortnite's server-side acceptance of your session depends on EAC producing signed proofs that only the real EAC can produce. Walking the chain:

### The chain of signatures

1. **Launcher → EAC** — `FortniteLauncher.exe` signs a session token (per [03 launcher](03-user-mode-launcher.md)) with a private key baked into the launcher's signed binary + rotated per Epic build.
2. **EAC Driver → Service** — Driver SELF_CHECK IOCTL signs (hash || nonce || bootCookie) with **ed25519 private key embedded in the driver** ([02 kernel driver](02-kernel-driver.md)).
3. **EAC Agent → Fortnite Shipping** — Agent's init callback produces an ed25519 signature over session state ([00 current-build notes](00-current-build-notes.md)). Private key for this is session-ephemeral and derived via ECDH with Epic's backend.
4. **EAC Service → Epic Datarouter** — Service posts telemetry signed by an authenticated TLS session, cert pinned ([16 telemetry](16-telemetry-endpoints.md)).
5. **EAC Backend → Game Server** — Epic's backend returns session-attestation tokens the game server verifies.

**Each link must be unforgeable from the client side.** Break any one and the chain's intent is compromised.

### What you'd need to forge a live Fortnite session

| Link | Required to break | Feasibility |
|-|-|-|
| 1 — Launcher session token | Steal launcher signing key OR patch Launcher to use your key | **Infeasible.** Launcher binary is signed with Epic's cert; patching it breaks its own signature check. |
| 2 — Driver SELF_CHECK ed25519 | Extract private key from signed `.sys` OR find reversal path to leak during runtime | **Infeasible.** Key is in VMProtect'd section. Even if extracted, backend verifies (hash matches public key record) so you'd need to rotate your driver's hash and get it on Epic's whitelist. |
| 3 — Agent init ed25519 | Compromise the ECDH key agreement OR extract ephemeral key from memory before use | **Hard.** ECDH exchange is with Epic's backend over TLS with pin. Breaking it = breaking TLS + pin + ECDH. See Part 3 for the theoretical attack. |
| 4 — Service → Datarouter TLS | MITM the pinned TLS connection | **Doable for observation** (Kaspersky SSL trick per [16](16-telemetry-endpoints.md)). **Not doable for forgery** — forging requests still needs valid session state from link 3. |
| 5 — Backend session attestation | Impersonate Epic's backend to your own game server | **Possible only in a private-server context** (your server trusts your emulated backend). **Not possible against Epic's own game servers.** |

**The practical conclusion:** live Fortnite server bypass requires either (a) compromising Epic's backend keys (nation-state-level access or insider threat), or (b) running your own full backend + your own patched client.

---

## Part 2 — Private server projects (the "(b)" path — real projects)

What the community actually ships.

### Project Reboot

Current state: **active, OG-season focused.** The main public Fortnite private server project.

Architecture:
- **Custom backend** reimplementing Epic's services: MCP (Master Control Program), Lightswitch, Matchmaking, Friends, Party, Catalog, XMPP, Game Session.
- **Patched `FortniteClient-Win64-Shipping.exe`** to point at the private backend + skip EAC integrity checks.
- **Hand-patched EAC binaries** that accept the emulator's ephemeral keys.
- **Specific chapter/season support** — most popular: Chapter 1 Season 5, Chapter 2 Season 1-2 (OG era).

What they skip:
- No live-server-equivalent anti-cheat. Integrity enforcement is client-side only (patched EAC returning success).
- Behavioral correlation via ML is not implemented.
- Shadow-ban mechanics don't exist.

Why they target OG seasons specifically:
- Pre-EAC-expansion Fortnite had weaker integrity (early seasons used BattlEye alongside EAC, less stringent kernel integration).
- Nostalgia market — the biggest private-server playerbase wants OG seasons.
- Epic's DMCA attention focuses on current-build piracy; OG-season private servers get less legal pressure.

Github-visible successor projects (names rotate as repos get DMCA'd):
- Reboot Launcher
- LawinServer / Project Lawin
- Momentum
- Neonite (API mock)
- Memento Mori
- Project Aurora

### What a complete Fortnite private server has to implement

The service catalog Epic ships, each of which the private server has to mock:

| Service | Purpose | Minimum viable implementation |
|-|-|-|
| Lightswitch | Feature flags per account per app | Static JSON return "service up" |
| MCP (Master Control Program) | Save data — Battle Royale profile, STW profile, Creative profile | Per-user SQLite + MCP profile JSON schema |
| Matchmaker | Session queueing + bucket assignment | Simple queue → start session |
| Session service | Active-session registry | In-memory session list |
| Friends | Friend list CRUD | Per-user friend table |
| Party | Party formation + state sync | WebSocket + state diff protocol |
| XMPP | In-game chat | Prosody or ejabberd configured |
| Catalog | Item Shop | Static JSON of configured items per season |
| Storefront | Entitlement grants | Grant-all or configurable |
| Entitlement | Who owns what | Per-user entitlement table |
| Fortnite Content | CDN for cosmetics/sounds/maps | Pre-cached CDN mirror |
| Launcher Services | Patch/update notification | Return "no updates" |
| Account | Login + profile | Custom auth → returns valid-looking tokens |
| OAuth Token | Access/refresh tokens | Hand-mint JWTs with keys the client is patched to trust |
| EpicGamesService (profile) | Display name, avatar | Per-user profile table |

**Estimate:** 10-30 KLOC of C# or Node.js to get a minimum-viable Chapter 1 OG season working. Active maintenance per Fortnite patch.

### EAC bypass approach in a private server

Specifically what Reboot-style projects do to make EAC not block the client:

1. **Launch bypass** — patch shipping exe to skip the EAC wrapper check, OR launch via `FortniteClient-Win64-Shipping.exe` directly (bypasses `_EAC.exe` wrapper, works for pre-signature-check builds).
2. **Integrity callback stub** — either stub EAC_x64.dll entirely (works for old builds without signature verification) OR patch the shipping exe to not verify the signature on EAC init callback (required for current builds).
3. **Backend keys** — replace Epic's pinned pubkey in the shipping exe with the private server's pubkey. Private server's backend signs session attestations with the matching private key.
4. **EOS SDK** — replace `EOSSDK-Win64-Shipping.dll` with a redirect version or stub that routes to the private backend.

Pattern you see in reality:
- Exact binary patches at known RVAs (changes per Fortnite build — Reboot-style projects maintain a per-build patch catalog).
- Hash-check skipping (EAC installer verifies its own files — patch out or substitute).
- Session continuation tokens issued by the private backend with the private server's signing key.

### Legal status

- Fortnite EULA prohibits private servers.
- Epic has issued DMCA takedowns + lawsuits against specific projects (Project Lawin targeted repeatedly).
- Most projects operate pseudonymously and host repos in jurisdictions with weaker IP enforcement.
- Playing on a private server doesn't risk your Epic account directly (the private server doesn't touch your Epic account), but the **tools to patch client binaries violate EULA**.

---

## Part 3 — Theoretical live-server attacks against Epic's keys

**Not practical attacks.** This is the "what would an advanced adversary need" threat model, for completeness.

### Attack 3.1 — Extract driver ed25519 private key

The driver signs SELF_CHECK with an embedded ed25519 private key. If extracted:

Steps required:
1. Reverse `EasyAntiCheat_EOS.sys` past the VMProtect layer around the signing function.
2. Find the 32-byte private key constant OR trace the derivation of a runtime-constructed key.
3. Extract.

Blockers:
- VMProtect devirt is a multi-week effort per build.
- The key may be split across memory + derived at runtime from a boot-cookie-sealed source.
- Even with the key, you need the matching **public key to be in Epic's whitelist on their backend**. The backend doesn't just verify "signature is valid" — it verifies "signature by expected key for this driver version." Rotating your signing key means Epic doesn't recognize your driver.

**What this gives you:** ability to forge SELF_CHECK responses locally. **Not enough** — the chain still requires live ECDH with Epic's backend for the session-ephemeral key in link 3.

### Attack 3.2 — Compromise ECDH session key during negotiation

Agent and backend do ECDH during session setup. If you can observe both sides:

Steps:
1. Patch EAC's pin check to allow MITM with your CA.
2. MITM the ECDH exchange.
3. Capture shared secret.
4. Use shared secret to sign subsequent messages as the agent.

Blockers:
- ECDH is ephemeral per session — key dies at session end.
- Backend verifies signatures against the agent's ECDH public key, which was the one sent in the handshake. If you MITM, you have to present your own ECDH pubkey to the backend, which the backend hasn't signed for this session.
- There's an implicit authentication binding — Epic's backend expects the ECDH to be signed by the driver's ed25519 (link 2). Without link 2, link 3 is rejected.

**Chain-break:** need link 2 + link 3 together.

### Attack 3.3 — Compromise Epic's HSM

Where Epic's backend signing keys actually live.

Blockers:
- HSMs with FIPS 140-2 Level 3+ don't export keys. Compromise requires either HSM-firmware vulnerability or physical access.
- Epic's HSMs are AWS CloudHSM / Azure Dedicated HSM / physical devices in their own datacenter. No public disclosure of exact setup.
- A compromise would be headline news. Hasn't happened.

### Attack 3.4 — EAC Oy signing cert leak (historical)

Circa 2020, an alleged leak of an older EAC-signing certificate circulated. Short-term impact — allowed rolling your own "signed" EAC.sys that loaded without SmartScreen warnings, pre-WDAC-blocklist.

Caveats:
- Microsoft revoked the cert within weeks.
- Current builds use rotated certs.
- WDAC catches any revoked-cert driver load regardless.
- The leaked cert was a **signing** cert — it signed binaries. **It wasn't the session-attestation key.** You still couldn't produce live-session signatures with it.

**The historical incident matters because** it shows that private-key material at the "publisher cert" level has leaked before. The deeper session-attestation keys have not (publicly).

### Attack 3.5 — Insider threat

Theoretical path with the highest practical likelihood. An Epic engineer with HSM access leaking keys. There's been no public evidence this has happened. Unverifiable.

### Attack 3.6 — Microsoft driver-signing abuse

MS-signed drivers inherit trust via the WHQL chain. Previously, several vulnerabilities in the attestation signing flow allowed malicious actors to obtain MS-signed drivers (reported extensively by Mandiant 2022-2023). None of those compromised EAC's specific session-attestation chain.

---

## Part 4 — The "almost works but doesn't" category

Real attacks that got partway but didn't close the full chain.

### "Patch the EAC_x64 init callback to return success + spoofed signature"

What it attempts: Bypass link 3 by producing a signature with a key the attacker controls.

Why it fails: Shipping exe verifies the signature against a pubkey **pinned in the shipping exe itself**. You'd need to also patch the shipping exe to accept your pubkey. Which is doable — but now you've modified the shipping exe, which:
- Fails EAC's integrity scan if EAC's driver is live.
- Is detected by Epic's backend via hash-reporting (the backend can request a hash of the shipping exe's .text in some session paths).

Partial mitigation: operate in a session where EAC is effectively disabled (achieved by also preventing the EAC service from loading). But then the backend's first "where is EAC" check fails → session rejection.

**Ends up being:** "patch shipping exe + disable EAC entirely" → the full private-server path, not a live-server bypass.

### "Dual-launch trick"

What it attempts: Run two Fortnite instances — one clean, one modified. Have the clean one authenticate while the modified one plays.

Why it fails: Session is tied to a specific process ID + launcher-issued token. The clean instance's session doesn't transfer to the modified instance. Attempts to share session tokens across processes trigger duplicate-session detection server-side.

### "MITM via network driver to replay session traffic"

What it attempts: Observe a legitimate session's traffic from a clean machine, replay it from a modified machine.

Why it fails: Every message has a per-session nonce bound to the ECDH-derived session key. Replay produces invalid MACs on the server side.

### "Use a BYOVD to disable EAC's kernel callbacks mid-session"

What it attempts: BYOVD to unregister EAC's `PsSet*NotifyRoutine` entries while the session is active. Then run cheats freely.

Partial success: unregistering the callbacks does work in principle. BUT:
- The driver's self-watchdog (`Wdog` module, [15.3](15-driver-raw-offsets.md#section-153--the-46-module-manifest)) checks that callbacks are still registered. Unregistering triggers a `GameTrust` or `IntegrityViolation` event.
- ETW-TI still emits events ([18](18-etw-ti-and-kernel-hazards.md)) even with callbacks unregistered.
- EAC's `CALLBACK_DUMP` IOCTL detects the unregistration (your callback addresses no longer in the list).

**Lives for seconds, not minutes.**

### "DMA card that spoofs its PCI config space"

What it attempts: External PCIe FPGA cheat that presents itself as a legitimate device (fake NVMe, fake GPU). Reads game memory via DMA, outputs ESP/aim to a second display.

Partial success, mostly for players without Kernel DMA Protection (KDP) enabled:
- EAC's PCI enum reads config space → sees the fake device's IDs.
- Device-level anomalies (unexpected vendor on an unusual slot, mismatched subsystem IDs) → soft flag.
- With KDP enabled, DMA attacks are neutralized at the hardware level.

Commercial DMA cards (Screamer, Spartan M.2, generic Chinese variants) keep rotating config-space fingerprints. Current 2026 state: effective against players without KDP + weak-fingerprint-correlation players; caught via behavioral correlation over time.

---

## Part 5 — Public exploit history (real published work)

### Mellow's EAC-agent code execution (2021-ish)

Mellow (handle only) published a writeup of an EAC agent vulnerability that allowed local code execution with EAC's privileges. Specifics:

- **Type:** Memory corruption in the agent's pipe parser.
- **Impact:** Attacker with a pre-existing foothold in the game process could execute code in the EAC agent's context.
- **Fix:** Patched by EAC within a build or two.

**What this teaches:** EAC's own code has bugs. Finding them requires the same reverse engineering depth covered in [15 driver raw offsets](15-driver-raw-offsets.md). Not a shortcut — worth the same effort as building a private server.

### Secret Club's EAC integrity-check vulnerability (various)

Secret Club published several EAC-specific research pieces, including one on integrity-check bypass via TOCTOU race. Pattern:

- **Attack:** Modify a module between EAC's hash-time and subsequent use.
- **Impact:** Transient modifications that EAC's periodic scan would miss.
- **Mitigation:** EAC moved to continuous verification + jittered intervals. Bug class still exists for specific windows.

### Capcom RTCore64.sys abuse (2019-2021)

The famous one. `RTCore64.sys` (MSI Afterburner) exposed arbitrary MSR R/W via IOCTL to any authenticated user. Used by:

- **Thousands of cheats** through 2020-2021.
- **Malware families** (BlackByte ransomware, LockBit, etc. — the "Bring Your Own Vulnerable Driver" technique mainstreamed here).
- **Legitimate security researchers** to demo the WDAC use case.

Timeline:
- Discovered publicly 2018.
- Microsoft added to WDAC vulnerable driver list ~2020.
- Still floats around with slightly different signing certs.

### CVE-2022-{various} — Dell DBUTIL_2_3.sys

Dell's BIOS update utility driver with arbitrary MSR + physical memory R/W. CVE assigned. Similar lifecycle:
- Signed with Dell's valid cert.
- Available via Dell update tools.
- WDAC-blocked eventually.
- Used by cheat development for a window of ~1.5 years.

### The BlackLotus UEFI bootkit

First widely-publicized UEFI bootkit that bypassed Secure Boot (via CVE-2022-21894 — the "Baton Drop" vulnerability in Windows Boot Manager).

Relevance to cheats:
- **Boot-level execution** before any anti-cheat.
- **Can patch kernel in memory** before PatchGuard initialization.
- **Persists** across OS reinstalls (lives in EFI System Partition).

Not publicly available as a cheat; sold on private forums for $5000+.

### CosmicStrand

Another UEFI implant, more stealthy than BlackLotus. Used by APT groups mostly, but the technique is adopted by elite cheat developers.

---

## Part 6 — The "things people actually ship" chart

Mapping realistic cheat categories to detection difficulty today:

| Cheat type | Real-world detection | Timeline to catch |
|-|-|-|
| Public user-mode-only cheats | Instant | Seconds to minutes per session |
| BYOVD-based kernel cheats (RTCore-era tier) | Fast | Session to hours |
| Manual-mapped kernel cheats (kdmapper-tier) | Medium | Days to weeks |
| Hypervisor-based cheats (SimpleVisor-derived) | Slow | Weeks to months |
| DMA-card cheats (Screamer tier) | Slow — behavioral mostly | Months with KDP off; indefinite with KDP on |
| Hardware input injectors (kmbox + arduino) | Slow — behavioral only | Months |
| Capture-card + second-PC + aim injection | Hardest to catch — behavioral only | Can run indefinitely at low skill level; months at high skill |
| UEFI bootkit cheats | Slowest | Years, if ever, by current EAC |
| SMM-based cheats | Theoretical, almost no real deployment | Essentially undetectable from OS |

**Practical reality:** every cheat caught eventually unless it's hardware-external. The variable is the time horizon. Commercial cheat markets price accordingly — public cheats are $5/week, private cheats are $50-200/week, UEFI/hypervisor cheats are $500-2000/week.

---

## Part 7 — Why "crack Epic's keys once and we win forever" is wrong

Even if someone leaked all of Epic's current keys:

- **Session attestation keys rotate per-season** (observed over years of public RE — the Ed25519 keypair changes between Fortnite chapters).
- **Backend state has nonces + timestamps** — a stolen key lets you forge sessions for a window (hours), not forever.
- **Epic can invalidate individual session IDs** server-side — mass-invalidate forged sessions the moment they're detected.
- **The ban list is key-independent** — forged sessions still get flagged by behavioral ML, and HWID bans apply regardless of cryptographic authenticity.

A successful key-compromise attack buys **a few sessions of free play before detection** and Epic rotating keys. Not "permanent cheat capability."

---

## Part 8 — The real asymmetry

Why does this matter? Because the pattern across every subsystem in this repo is the same:

- **Cryptographic signatures protect specific events** (session attestation, driver integrity).
- **Behavioral ML protects classes of anomaly** (impossibly consistent aim, impossibly fast reactions).
- **HWID binding protects accounts** across hardware.

A cheat developer can beat one layer but not all three simultaneously for long. **Each session is probabilistic protection; multi-session correlation closes the window.**

**The practical cheat developer's problem:** not "how do I bypass EAC" but "how do I bypass EAC in a way that still looks statistically normal across hundreds of sessions." The second part is where almost every cheat eventually fails.

---

**Next:** [21 — Real exploits and case studies](21-real-exploits-case-studies.md)
