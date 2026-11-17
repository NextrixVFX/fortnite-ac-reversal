# 00 — Current-build notes + Fortnite EAC history

Changelog from historical EAC (2018 Fortnite integration) to what's shipping on current Fortnite builds (late-2026, agent version strings around `EAC_2026_*`). Read this before the architecture docs so you know which details are new.

Includes Fortnite-specific EAC history (BattlEye → dual-stack → EAC-only → EAC-EOS).

---

## Part 1 — Fortnite's anti-cheat history

| Period | Anti-cheat | Notes |
|-|-|-|
| 2017 (launch — early BR) | **BattlEye** | Original Fortnite AC |
| 2017-2018 | BattlEye + EAC experiments | Epic began testing EAC integration before acquiring EAC |
| 2018 (October) | **Epic acquires Easy Anti-Cheat Oy** | Finnish company founded 2006; Epic now owned both the game and the AC |
| 2018-2021 | **BattlEye + EAC dual stack** | Both ACs ran simultaneously; cheat devs had to defeat both |
| 2021 | **EAC only** (BattlEye dropped) | Epic consolidation move |
| 2022+ | EAC migrating Classic → EOS variant | `EasyAntiCheat_EOS.*` stack |
| 2023+ | Ed25519 signatures, VMProtect 3.x, bundled hook baselines | |
| 2024+ | ETW-TI subscription, `env_worker` drift detection | |
| 2024+ | TPM attestation via `EacQuoteKey` | Hardware-rooted trust |
| 2025+ | `PsSetCreateProcessNotifyRoutineEx2` with veto | Win11 23H2+ only |
| 2025+ | AES-256-GCM rules.bin | Up from AES-128-CBC |
| 2025+ | Daily correlation cadence | Down from weekly ban waves |

The dual-stack period (2018-2021) was unusual — both ACs ran in parallel. Each caught different cheat categories. **Fortnite private-server emulators specifically target the pre-2021 dual-stack configurations or earlier where defeat conditions differ.**

---

## Part 2 — Current-build headline changes

### Kernel driver

- **Expanded BYOVD matching.** `DRIVER_LIST` used to return name + hash. Now also returns image size, signer cert thumbprint, and the Microsoft WDAC vulnerable-driver block-list state. Renaming your vulnerable driver buys you nothing.
- **`PsSetCreateProcessNotifyRoutineEx2` on win11 23H2+.** The newer kernel surface lets EAC veto process creation before it starts rather than just observe it.
- **ObRegisterCallbacks altitude moved.** Up from the old `"321000"` string into a higher band to avoid collisions with newer gamer-focused AV products.

### Crypto

- **rules.bin moved from AES-128-CBC to AES-256-GCM.** Key derivation is still HKDF-SHA256 but with a longer output and a different `info` string.
- **Signature outside the ciphertext changed from RSA-PSS to Ed25519.** Smaller sig (64 bytes vs 256), same guarantee, faster verify.

### Scanners

- **Dual frame-capture path.** DXGI OutputDuplication plus Win32 `Graphics.Capture` on win11.
- **Integrity hash set expanded.** Current builds hash `ntdll.dll`, `kernelbase.dll`, `win32u.dll`, and `dxgi`/`d3d11` stubs on top of the game's modules.
- **Hook-detector baselines moved on-DLL.** From `\KnownDlls` (tamperable) to bundled known-good pages shipping with the agent.
- **New `env_worker` thread.** Runs on ~30s cadence doing an environmental-consistency pass — pulls SMBIOS, MAC, disk serials, machine GUID, compares against session-init snapshots, flags drift. **Spoof-detector hedge.**
- **ETW-TI integration.** Driver subscribes to the `Microsoft-Windows-Threat-Intelligence` ETW provider for kernel-asserted suspicious events.

### Telemetry

- **All transport consolidated to `api.epicgames.dev`.** Legacy `service.easyanticheat.net` endpoints resolve but return 410.
- **AEAD on the pipe.** Chacha20-Poly1305 replaced plain Chacha20.
- **Compression with a baked dictionary.** Telemetry body is zstd with a shared dictionary (~8 KB) baked into the agent DLL.
- **New flag family `0x1Cxx` — environmental fingerprint anomalies.**
- **Daily correlation cadence.** Ban waves still exist but shortened from weekly to daily. High-severity flag chains trigger near-realtime bans.

### Remote scanner loading

- **`REMOTE_MODULE_LOAD` pipe opcode.** The launcher can push signed auxiliary scanner DLLs to the agent at runtime, pulled from `modules-cdn.eac-prod.on.epicgames.com`. Epic deploys new detections without shipping a new EAC version.

### Fortnite-side

- **UE5-current integration.** Classic `IOnlineAntiCheatCommon` and `IAntiCheatModularFeature` interfaces, same binding pattern.
- **Shipping exe signature-check on EAC init callback.** Current builds verify not just that EAC's init returned success but also that the init callback carried an Ed25519 signature over session state that only the real EAC can produce. This is what breaks the simple-stub emulation approach on live Fortnite.

---

## Part 3 — What's unchanged

For completeness, because people assume lots of things changed that didn't:

- **Callback APIs.** `PsSetCreateProcessNotifyRoutineEx` (or Ex2), `PsSetCreateThreadNotifyRoutine`, `PsSetLoadImageNotifyRoutine`, `ObRegisterCallbacks`, `CmRegisterCallbackEx`. Same surface, same semantics.
- **Handle strip mechanism.** Same `ObRegisterCallbacks` pre-op pattern, same strip mask.
- **VAD walker approach.** Still the gold standard for catching manually-mapped modules.
- **Caller authentication model.** User-mode agent still has to present a signed session blob to the driver at CREATE time.
- **VMProtect 3.x as primary obfuscator.** Ultra-mutation + import protection enabled.
- **No BSOD policy.** The driver still doesn't crash legit users on self-hash mismatch — it flags and reports, backend decides.

---

## Part 4 — What's gone

- **BattlEye.** Dropped around 2021.
- **Legacy `easyanticheat.net` transport.** DNS still resolves, HTTP 410 on new sessions.
- **AES-128-CBC rules.bin.** Replaced by AES-256-GCM.
- **RSA-PSS rules.bin signature.** Replaced by Ed25519.
- **Trusting `\KnownDlls` for hook-detector baselines.** Bundled baselines now.

---

## Part 5 — Milestone cheat events (what triggered which EAC changes)

Specific events that triggered observable EAC changes:

### 2019 — Fortnite Winter Cheat Wave

- Massive hypervisor cheat deployment during the holiday season.
- Epic's response: emergency patch adding anti-VM timing checks in mid-December.
- Set the precedent for "major cheat events trigger mid-season EAC updates."

### 2020 — World Cup qualifier scandal

- Multiple accused cheaters in FNCS qualifiers.
- Epic rolled back prize distributions.
- Established the payout-hold policy still in use.

### 2021 — RTCore64.sys crackdown

- Microsoft added RTCore64 to WDAC block list.
- Many Fortnite cheats relied on it.
- Precipitated the move toward manual-mapped drivers + hypervisor cheats.

### 2022 — LAPSUS$ Nvidia breach

- Nvidia code-signing certs leaked.
- Several cheats briefly signed with leaked certs.
- Microsoft revoked within weeks.
- Reinforced the WDAC-at-load-time enforcement pattern.

### 2023 — BlackLotus era

- First publicly-disclosed UEFI bootkit bypass of Secure Boot (via CVE-2022-21894).
- Elite cheat vendors adopted bootkit persistence.
- EAC response: TPM attestation + Measured Boot PCR drift detection.

### 2024 — Project Reboot DMCA wave

- Epic went after Project Reboot derivatives aggressively.
- Multiple repos taken down.
- Private-server operators moved to pseudonymous hosting.

### 2025 — DMA proliferation

- Chinese FPGA DMA cards became $200 commodity.
- Fortnite ban wave specifically targeting DMA players.
- EAC added PCI configuration space enumeration + IOMMU state reporting.

---

## Part 6 — Version-triage quick tips

To figure out which EAC build you're staring at before you start reversing:

- **`SplashScreen.png` in the bundle folder** often changes shape when EAC hits a version boundary. Not reliable alone but useful for rough dating.
- **Agent build string in telemetry packets** (`EAC_2026_MM_DD` pattern). Lift from a pipe capture.
- **Signer cert thumbprint on `.sys` + `.dll`.** `signtool verify /pa /v`. Thumbprints and sign dates narrow down the window.
- **IOCTL dispatcher size.** Current-build driver dispatcher is bigger than historical (new IOCTLs added).
- **Imports tab in IDA on the `.sys`.** 5-ish imports → current (name-resolution). 50+ imports → pre-2019.
- **Current rules.bin file size + magic** (`EACR` header + GCM structure + Ed25519 sig at end = current-build).

---

## Part 7 — What might come next

Reasonable predictions based on trajectory (2026-2028):

- **Deeper TPM 2.0 integration** — attestation beyond just EK readout, into PCR-based policy enforcement.
- **Confidential compute** interactions — Intel TDX / AMD SEV-SNP for isolating EAC's own agent from hypervisor cheats.
- **CET integration** — using Control-flow Enforcement Technology against ROP-style cheats.
- **DRTM (Dynamic Root of Trust)** adoption — Windows' Secure Launch becomes EAC's baseline measurement.
- **Vulkan / explicit API hooks** — DXGI frame capture may extend to Vulkan swap chains.
- **AI/ML on the client side** — possible, with lightweight inference running locally to flag in-session anomalies pre-correlation.
- **Longer and more opaque correlation windows** — moving from daily to continuous correlation with Bayesian inference.

None guaranteed; all plausible based on 2026 trends.

---

## Part 8 — Build-triage signals (quick-reference)

| Signal | Location |
|-|-|
| EAC agent build string | Pipe `HELLO` message; also `.rdata` of `EasyAntiCheat_x64.dll` as UTF-8 `"EAC_YYYY_MM_DD"` |
| EAC driver build string | `.rdata` of `EasyAntiCheat.sys`, UTF-16 |
| Fortnite build version | `FortniteGame\Content\Build.version` (text file) OR `.rdata` of shipping exe |
| Fortnite UE engine version | UE5 build string in shipping exe's version info |
| EOS SDK version | `FileVersion` resource of `EOSSDK-Win64-Shipping.dll` |
| Driver signing cert thumbprint | `signtool verify /pa /v` on the `.sys` |
| Driver sign date | `signtool verify /pa /v` timestamp signature |
| Rules.bin build-id | First 8 bytes after the `'EACR'` magic + version field |

Match 3+ of these to pin down the exact build context.

---

**Next:** [01 — On-disk inventory](01-on-disk-inventory.md)
