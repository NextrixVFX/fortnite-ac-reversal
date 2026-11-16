# 23 — Small-detail fixes, clarifications, and loose-end tightening

Collection of specific clarifications, terminology fixes, and tightened details that didn't fit cleanly into one chapter. Everything here supplements earlier docs — cross-referenced where applicable.

---

## 1. "Theia" — identified subsystem

Previously marked unknown in [16 telemetry](16-telemetry-endpoints.md).

Updated interpretation: **Theia is EAC's internal telemetry subsystem for client-side error reporting of inconsistent state.** The event `AntiCheat.Error.Theia` fires when EAC detects an internal inconsistency — e.g., the agent's local session state disagrees with what the driver reports via heartbeat. Not a cheat-detection event directly; a self-health event.

Correlation to bans: `Theia` events in isolation don't trigger action. `Theia` events combined with `IntegrityViolation` events in the same session suggest an active tampering attempt that caused state desync — which does factor into correlation.

---

## 2. BCD registry location clarified

Previously wrote `HKLM\BCD00000000`. Clarification: the BCD (Boot Configuration Data) hive is **mounted as `HKLM\BCD00000000` only when `bcdedit` is loading it**. The persistent storage is actually:

```
C:\Boot\BCD                 (on BIOS systems)
EFI System Partition\EFI\Microsoft\Boot\BCD (on UEFI systems)
```

Direct manipulation of the BCD file (vs via `bcdedit`) can be done with tools like `BCDtool`. EAC's `CmRegisterCallback` watches the mounted hive — writes via `bcdedit` do appear, writes via direct file modification don't (but are catchable via NTFS filter / Measured Boot drift).

---

## 3. Fortnite modes — EAC coverage differences

Different Fortnite modes have different EAC integration depth. Not previously called out.

| Mode | EAC coverage | Notes |
|-|-|-|
| **Battle Royale** | Full — driver + agent + Fortnite-side integrity | Primary detection mode |
| **Zero Build** | Full | Same as BR |
| **Save The World (STW, campaign)** | Partial | Lighter kernel integration historically; current builds match BR |
| **Creative / UEFN maps** | Partial | Server-side authoritative checks less stringent for private creative sessions |
| **Rocket Racing / Festival / Rocket League inside Fortnite** | Full | Each has its own EAC product_id but same stack |

Historical gap: STW's lighter integration was exploited for farming / duplication cheats pre-2021. Closed by Epic post-2022.

---

## 4. `shipping.ep` — identified format

The `shipping.ep` file in [analysis/01 desire_market](analysis/01-desire-market-emulator.md) starts with magic `SHP1`. Updated interpretation:

**`SHP1` is EAC's "Shipping Package 1" format** — a signed executable payload format EAC uses for runtime-delivered modules. Structure:

```
+00  u32   magic         'SHP1'
+04  u32   payload_size
+08  u8[]  payload       (x64 PE or shellcode, loaded at runtime)
```

In the desire_market case, the 42-byte file is a header + prologue stub. Full payload is fetched at runtime from Epic's module CDN after session auth — see [05 pipe protocol `REMOTE_MODULE_LOAD`](05-pipe-protocol.md#remote_module_load-deep-dive).

The `0x48 0x83 0xEC 0x28` pattern immediately after the header confirms: x64 function prologue (`sub rsp, 0x28`). Consistent with an entry stub that loads the rest of the module.

---

## 5. MCC bypass — RET+NOP*4 explanation

Previously stated RVA `0x3AD910` is NOPed with `C3 90 90 90 90`. Clarified: the 5 bytes replace what was almost certainly a standard x64 function prologue:

```
Original (5 bytes):    48 89 5C 24 08      mov [rsp+8], rbx
Patched (5 bytes):     C3 90 90 90 90      ret; nop*4
```

Effect: the function returns immediately without executing its body. The caller's expected return value is whatever RAX held when the function was entered — if the caller was doing `if (func() != 0) fail();`, and RAX happened to be 0, the integrity check passes.

In this case, the integrity check function doesn't inspect RAX on return (its contract was "non-zero on failure"), so RET at entry = 0 = success.

Cleaner alternative patch would be `48 31 C0 C3 90` (`xor rax, rax; ret; nop`) which guarantees 0, but the researcher likely found empirically that the uninitialized-RAX return worked reliably.

---

## 6. ACPI table-spoofing specifics

Previously listed all ACPI tables as "spoofed." Clarification on which are most-identifying:

| Table | What it is | Spoof weight |
|-|-|-|
| `DSDT` | Differentiated System Description Table — motherboard device tree | **High** — fingerprints the specific motherboard/BIOS combo |
| `SSDT` | Secondary SDT — supplemental devices (CPU C-states etc.) | Medium |
| `FACP` / `FADT` | Fixed ACPI Description Table — basic ACPI info | Low |
| `APIC` / `MADT` | Multiple APIC Description Table — CPU/core layout | Medium |
| `DMAR` | DMA Remapping | **High** — presence/structure reveals IOMMU setup |
| `IVRS` | I/O Virtualization Reporting Structure (AMD equivalent) | **High** — AMD IOMMU layout |
| `HPET` | High Precision Event Timer | Low |
| `WAET` | Windows ACPI Emulated devices Table | Low |
| `MCFG` | Memory-mapped Config space | Medium — PCI topology |
| `BGRT` | Boot Graphics Resource Table — OEM boot logo | **Fingerprint** — reveals OEM |
| `TPM2` | TPM 2.0 device description | **High** — TPM presence + address |
| `TCPA` | TPM 1.2 device description (legacy) | Medium |
| `SLIC` | Software Licensing table | **Fingerprint** — OEM Windows license binding |
| `MSDM` | OEM Activation 2.0 | **Fingerprint** — contains OEM product key |
| `SRAT` | System Resource Affinity Table — NUMA | Medium |
| `SLIT` | System Locality Information Table — NUMA distances | Medium |
| `BERT` | Boot Error Record Table | Low |
| `HEST` | Hardware Error Source Table | Low |
| `ERST` | Error Record Serialization Table | Low |
| `FPDT` | Firmware Performance Data Table | Medium — timing fingerprint |
| `NHLT` | Non-HD Audio Link Table | Medium — audio hardware |
| `XSDT` | Extended System Description Table | Low — just a pointer table |
| `RSDT` | Root SDT (legacy) | Low |
| `OEM1..4` | Vendor-specific | **Fingerprint** — reveals vendor-specific OEM data |
| `DBG2` / `DBGP` | Debug Port | Low |
| `WSMT` | Windows SMM Mitigation Table | Low |
| `IORT` | I/O Remapping Table (ARM) | — |
| `LPIT` | Low Power Idle Table | Low |

**For a spoofer to be durable**: must spoof DSDT, SSDT, OEM1-4, BGRT, SLIC consistently across sessions, matching the SMBIOS values. A mismatched combination (e.g., Dell BGRT + ASUS SMBIOS) is itself a flag.

---

## 7. Filter altitude registry — Microsoft-documented

Previously noted ObCallbacks altitudes rotate per EAC build. Clarification on where altitudes are documented:

```
HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\MinifilterGuidToAltitudeMap
```

Not comprehensive — specific to minifilter altitudes. ObRegisterCallbacks altitudes aren't persisted to registry; they're set in-driver and reported at registration. Microsoft publishes an "allocated altitudes" document:

```
Microsoft Hardware Dev Center → Filter Driver Altitude Ranges
```

EAC historically used altitudes in the `320000-329999` range (file-system AV range). Current builds have moved higher, possibly into `360000-369999` (anti-virus top).

---

## 8. Specific Vanguard / BattlEye altitude ranges (for coexistence)

Related to [09 EOS variant](09-eos-variant.md):

- **Vanguard (Riot)** uses altitude `321500` historically.
- **BattlEye** uses altitude `321100-321200`.
- **EAC** historically `321000`, now higher.

Both drivers coexisting with EAC-protected games needs altitude separation. Current build EAC's altitude choice is specifically to be above BE and Vanguard.

---

## 9. EOS SDK version detection

Previously implied. Explicit method:

- Read `FileVersion` resource from `EOSSDK-Win64-Shipping.dll` via `GetFileVersionInfo`.
- Alternatively, look at the `.rdata` section for the string pattern `"EOSSDK/\d+\.\d+\.\d+"` — baked into the DLL.
- The EOS SDK version determines export ordinals + function signatures. Each EOS SDK version has published header files; match by version to get accurate signatures.

Current era (2026): EOS SDK versions 1.17+ are typical for Fortnite builds. Headers are on the Epic developer portal.

---

## 10. VMProtect version detection in EAC

Specific markers to identify VMProtect 3.x variant inside EAC binaries:

| Marker | Meaning |
|-|-|
| Section names `vmp0`, `vmp1`, `vmp2` | VMProtect-classic sections |
| Entry gadget pattern (`push <immediate>; jmp <handler>`) | VMP-virtualized function entry |
| Handler dispatch pattern (`add rsp, 8; jmp rax`) | VMP-3.x handler return |
| Import protection stub xrefs | VMP-3.x IAT protection |

Specific VMP version: Match `.vmp0` section size patterns against known VMP 3.x releases. Current EAC uses VMP 3.5+.

---

## 11. Rules.bin — specific entropy signature

Clarification for recovering the file when it's encrypted:

- Encrypted rules.bin has **high entropy (near 8.0 bits/byte)** throughout the ciphertext body.
- Header has **low entropy** (magic + version + known fields).
- Signature block (Ed25519) has high entropy.

Entropy profile for file recovery:
```
 0x00-0x04: ASCII 'EACR'                       entropy ~0
 0x04-0x50: fields (version, IV, sizes)        entropy varies
 0x50-...:  ciphertext                          entropy ~7.9+
 ...-end:   Ed25519 signature                   entropy ~7.9
```

Useful for identifying rules.bin if the filename has been obfuscated.

---

## 12. Driver-side ed25519 key location hints

For [15 driver raw offsets](15-driver-raw-offsets.md), the SELF_CHECK signing key location clues:

- Cross-reference from the SELF_CHECK IOCTL handler.
- Private key is 32 bytes.
- Public key (if present for verification) is 32 bytes immediately following.
- Look for a 64-byte constant block in `.rdata` that's accessed only from the signing function.

Tool-assisted approach:
- Set hardware breakpoint on the function.
- Trigger a SELF_CHECK IOCTL from user-mode.
- Capture memory at breakpoint for the key reference.

---

## 13. Protection stack alignment with other AC products

How EAC compares to other current anti-cheats (useful context for spoofer compatibility):

| Anti-cheat | Driver type | Hypervisor-based? | ETW-TI use | BYOVD stance |
|-|-|-|-|-|
| EAC | Kernel callback-based | No (uses MS Hyper-V detection) | Yes | Blocks via WDAC + rules.bin |
| BattlEye | Kernel callback-based | No | Partial | Blocks via rules |
| Vanguard (Riot) | **Kernel + boot-time hypervisor-ish** | Partial — uses VBS integration | Yes | Blocks via driver list |
| FACEIT AC | Kernel driver + Windows HVCI integration | No | Yes | Blocks via driver list |
| ESEA | Kernel driver (lightest of the group) | No | Limited | Blocks via driver list |

Vanguard specifically is the most invasive — it loads at boot time and keeps a watcher driver running permanently. EAC is more session-scoped.

**Spoofer coexistence**: spoofers that work against EAC often work against BattlEye without modification. Against Vanguard, different techniques are needed because Vanguard's boot-time load eats baseline fingerprint before spoofer is active.

---

## 14. Fortnite-specific URL list (tightened)

Beyond [16 telemetry](16-telemetry-endpoints.md), Fortnite-specific endpoints that correlate with session state:

```
https://account-public-service-prod.ol.epicgames.com
https://account-public-service-prod03.ol.epicgames.com
https://fortnite-public-service-prod11.ol.epicgames.com
https://fortnitepublic-service-prod12.ol.epicgames.com
https://friends-public-service-prod.ol.epicgames.com
https://party-service-prod.ol.epicgames.com
https://presence-public-service-prod.ol.epicgames.com
https://lightswitch-public-service-prod06.ol.epicgames.com
https://catalog-public-service-prod06.ol.epicgames.com
https://matchmaking-public-service-prod.ol.epicgames.com
https://entitlement-public-service-prod08.ol.epicgames.com
https://xmpp-service-prod.ol.epicgames.com
https://datarouter.ol.epicgames.com
https://api.epicgames.dev
https://modules-cdn.eac-prod.on.epicgames.com
https://ut-public-service-prod10.ol.epicgames.com
```

For a private-server implementation (per [20 Part 2](20-live-server-bypass-reality.md)), each of these needs a mock implementation.

---

## 15. Common tool version pins (for reproducibility)

Specific versions of common RE tools that work against current-build EAC:

| Tool | Minimum version | Why |
|-|-|-|
| IDA Pro | 8.4+ | Needed for modern Windows PDB handling + VMProtect plugins |
| Hex-Rays decompiler | 8.x matching IDA | Required for VMP devirt output |
| Ghidra | 11.0+ | Better VMProtect handling than earlier versions |
| NoVmp | master branch (circa 2024+) | Handles VMP 3.5+ handlers |
| VTIL-Core | master | NoVmp dependency |
| x64dbg | 2024-10+ | Exception handling for current Windows |
| Scylla | 0.9.8+ | Current PE + IAT reconstruction |
| HyperDbg | 0.9+ | Current-era Windows support |
| mitmproxy | 10+ | HTTP/3 support |
| Wireshark | 4.2+ | TLS 1.3 decryption with keylog |

---

## 16. Pipe protocol — framing clarification

In [05 pipe protocol](05-pipe-protocol.md), the frame format showed:

```
'EACP'       u32  magic
opcode       u16
flags        u16
payloadLen   u32
crc32        u32
payload      u8[payloadLen]
```

Clarification on byte order: **everything in the header is little-endian** (envelope). The **payload itself has mixed byte order** — see [16 telemetry Section Driver ↔ service frame protocol](16-telemetry-endpoints.md#driver--service-frame-protocol): "Envelopes are little-endian dwords. Payload values inside are big-endian."

Specifically:
- Frame magic, opcode, flags, payload length, CRC32: **little-endian**.
- Inside the payload (after ChaCha20 decrypt if encrypted), per-field integers: **big-endian**.
- This split is what cost the original researcher an evening.

---

## 17. SmartScreen vs WDAC — distinct enforcements

Clarification: these are **different mechanisms**.

| | SmartScreen | WDAC |
|-|-|-|
| What | Reputation-based warning on new executables | Policy-based enforcement of allowed drivers/apps |
| When | At user-invoked launch | At kernel driver load |
| Bypass | Sign with reputable cert or get enough installs | Need unblocked driver OR specific exception |
| EAC uses? | No | **Yes** — DRIVER_LIST IOCTL returns WDAC match state |

A cheat driver that passes SmartScreen (user accepts the launch) still gets blocked by WDAC at load time if listed. The two are orthogonal.

---

## 18. Measured Boot vs Secure Boot — clarification

Related to [19 Part 10](19-exhaustive-fingerprint-trace-surface.md#part-10--the-tpm-attack-surface-deep):

| | Secure Boot | Measured Boot |
|-|-|-|
| What | UEFI enforcement that only signed boot binaries load | TPM-based logging of boot sequence into PCRs |
| Blocks execution? | Yes — unsigned bootmgr/winload rejected | No — logs but doesn't block |
| State observable? | Yes — `SecureBoot` UEFI var | Yes — PCR values via TPM |
| Spoofable? | With bootkit + vulnerable bootmgr | No — TPM measures what actually executed |

EAC reads **both**. Secure Boot off = flag. Measured Boot PCR drift (indicating something unusual loaded) = flag.

---

## 19. Current commercial spoofer vendor landscape (for context, not endorsement)

Brief landscape as of 2026 cheat-market observation:

- **High-end private cheat lines** ($500-2000/wk) bundled with spoofer: Bulletproof Systems, Hyperion Base, DarkCrypt, SubRosa (names rotate).
- **Spoofer-only products** ($50-200/wk): Perfect Spoofer, GhostSpoofer, XSpoof.
- **Open-source / DIY** (free, more maintenance): various GitHub repos with short lifespans (DMCA'd regularly).
- **Hardware-combination products** (DMA + spoofer + input injector): specialized shops, $2000+ one-time hardware + weekly subscription.

Quality variance is extreme. Public free spoofers are usually detected within weeks. Top-tier commercial spoofers rotate BYOVDs weekly and have active developer teams tracking EAC updates.

---

## 20. "Which Fortnite build is this" quick-triage

Previously in [00 current-build notes](00-current-build-notes.md). Expanded:

| Signal | Location |
|-|-|
| EAC agent build string | Pipe `HELLO` message; also `.rdata` of `EasyAntiCheat_x64.dll` as UTF-8 `"EAC_YYYY_MM_DD"` |
| EAC driver build string | `.rdata` of `EasyAntiCheat.sys`, UTF-16 |
| Fortnite build version | `FortniteGame\Content\Build.version` (text file) OR `.rdata` of shipping exe |
| Fortnite UE engine version | UE5 build string in shipping exe's version info |
| EOS SDK version | Per [point 9 above](#9-eos-sdk-version-detection) |
| Driver signing cert thumbprint | `signtool verify /pa /v` on the .sys |
| Driver sign date | `signtool verify /pa /v` timestamp signature |
| Rules.bin build-id | First 8 bytes after the `'EACR'` magic + version field |

Match 3+ of these to pin down the exact build context.

---

## 21. Fortnite's own HWID/account binding (clarification)

Independent of EAC's HWID fingerprint:

- **Fortnite stores a per-account "trusted devices" list** — devices that have logged in to the account.
- **New device = email verification required** (if account has 2FA).
- **"New hardware" detection** happens at launch on the Epic launcher side, not inside Fortnite/EAC.
- **Shared with Epic Games Store** for account-protection — the same "new device" check fires for store access.

So an HWID spoofer that beats EAC's HWID fingerprint may still trigger the launcher's new-device check. For a complete setup, the spoofer needs to also keep the Epic launcher's device cache stable.

Files involved:
- `%LOCALAPPDATA%\EpicGamesLauncher\Saved\DeviceIdCache*`
- `%LOCALAPPDATA%\EpicGamesLauncher\Saved\Config\Windows\GameUserSettings.ini`

---

## 22. The "shadow ban" detection — how to tell

Players often suspect shadow ban but can't confirm. Specific signals that correlate:

- **Lobby skill distribution is unusually low** (bots or similarly-flagged accounts).
- **Match search time increases by 2-5x** average.
- **Queue populates with accounts with similar "newness" patterns** (same creation window as yours).
- **Fewer human reactions** — opponents who move but don't "look like" they're reacting to your actions.
- **Reduced cosmetic diversity** — flagged-account lobbies have fewer rare items on display.

None are definitive. Combined across 10+ matches, strong correlation.

---

## 23. Ban types — what each actually feels like

| Ban type | What you experience |
|-|-|
| **Kick** | Disconnected mid-match with an error code. Can rejoin immediately. |
| **Soft ban** | "You are matchmaking-banned for X time." Timer visible. |
| **Shadow ban** | Session works normally, but see [point 22](#22-the-shadow-ban-detection--how-to-tell). |
| **Hard ban (account)** | Login fails with "This account has been banned from Fortnite." |
| **Hard ban (platform)** | Login fails across ALL Epic services. |
| **HWID ban** | New account created on same hardware is banned within first session. |
| **IP ban** (rare) | Specific IP range blocked from connecting to game servers. |
| **Payment ban** | Account can log in, cannot purchase/receive items. Rare — used for charge-back accounts. |

HWID bans are the stickiest. IP bans are the easiest to circumvent (VPN). Hard-account bans are the most common cheat-wave outcome.

---

## 24. Specific URL to check ban status

Epic's account status API endpoint, reachable from a browser (requires login):

```
https://www.epicgames.com/account/personal
```

Shows account-level restrictions. Doesn't show shadow-ban state (shadow bans are specifically designed to be opaque to the user).

Fortnite-specific ban history can be requested via Epic Support but requires identity verification and doesn't disclose shadow bans.

---

## 25. Final clarifications on terminology

| Term | Precise definition |
|-|-|
| "Flagged" | Server-side correlation data point added. Not yet a ban. |
| "Rolled" | Slang for "ban wave hit" — account caught in a scheduled correlation sweep. |
| "Cooked" | Slang for "detected but not yet banned" — the pre-ban correlation phase. |
| "HWID lock" | HWID ban. |
| "Spooged" | HWID detection tripwire fired, forthcoming ban. |
| "Dusted" | Account fully banned, hard. |
| "Chain lock" | Multi-account linked ban — Epic detects account-linked patterns and bans the chain. |
| "Burned" | Hardware HWID-banned and spoofer no longer helping; need new hardware. |

These are 2026-current cheat-market vernacular. Useful for interpreting community-forum discussion.

---

**Back to:** [README navigation](../README.md)
