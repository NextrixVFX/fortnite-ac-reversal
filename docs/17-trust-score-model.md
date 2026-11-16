# 17 — Trust-score model & per-handler feature flags

How EAC's backend decides what detection runs on **your** machine, and how that interacts with your spoofer/cheat/driver.

The score is server-side. The client never sees it. The driver and service **feed** it. The feedback loop is which handlers fire on your next session.

---

## The three inputs

### 1. Certificate trust state of the machine

Driver walks Windows trust stores + Wintrust policy plumbing. See [15.6](15-driver-raw-offsets.md#156--trust-score-plumbing) for the specific string offsets.

**What this means operationally:**

- Every signed driver on your machine is a data point.
- Signed cheat drivers from 2016 with leaked / revoked certs show up as trust-positive but fingerprint-negative.
- A fresh clean Windows install with only Microsoft + major vendor signers has the highest baseline trust.
- A machine with many third-party / unknown signers has lower baseline trust.

### 2. TPM attestation

EAC captures the TPM endorsement key, requests PCR quotes signed by the AIK (Attestation Identity Key), binds the attestation to the EAC session id. Controlled by registry keys:

```
SYSTEM\CurrentControlSet\Services\Tpm\PlatformQuoteKeys
EacQuoteKey
AttestationKey
SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS\Attestation
```

**What this means operationally:**

- Quotes are **cryptographically bound to physical TPM state.** A running hypervisor / tampered boot changes the PCR values → different quote → anomaly.
- The HWID isn't "just a text string" anymore when TPM attestation is in play. It's a cryptographic proof of boot state.
- Spoofers that don't address TPM (most don't) report consistent TPM-quote values across sessions. If the rest of the HWID changes but the TPM quote doesn't, the backend knows it's the same machine with a spoofer running.

### 3. Per-handler feature flags (the live-rotation dial)

This is the one most people don't know about.

The flattened command dispatcher at `0x18C0E6 – 0x18FE5D` ([15.2.e](15-driver-raw-offsets.md#152e--flattening--selector--kill-switches)) implements a per-handler feature-flag bit. Every detection routine checks its own flag before running:

```asm
mov  dl, byte ptr [r11+2]      ; flags byte from request record
mov  eax, r10d; shl eax,5; add eax,r10d; neg eax
xor  cl, 0x55                   ; shift1 = -(33*k) ^ 0x55
shr  dl, cl                     ; -> flags >> shift1
imul ecx, r10d, 0x3C
xor  cl, 0x1F                   ; mask = (k*0x3C) ^ 0x1F
and  cl, dl                     ; test = flags & mask
je   <skip handler>             ; == 0 -> handler is OFF
cmp  edx, 1                     ; == 1 -> primary path
```

**The feature-flag byte comes from the request record (`record+2`).** The request record is pushed from server-side to the driver per session. **The backend decides per-session which handlers fire.**

---

## What this means for "bypassing" EAC

If you bypass one check, you haven't bypassed the system. **The backend just rotates a flag.**

Consider a specific case: you build a spoofer that defeats `NtfL` (load-image notify). The first session, `NtfL` fires, finds nothing suspicious. The backend's correlation model notices "this machine had many driver loads in previous sessions, but none now — anomaly." Next session, the backend sets a flag turning on `SmBf` (SMBIOS fingerprint) with more granular checks + `WfpC` (WFP callouts) for network-level anomaly correlation. You might not even notice because you successfully defeated `NtfL`.

This is why "my cheat works, I tested it" doesn't mean "I'm safe." **What ran on your test session is not what will run on your next session.**

---

## Operational signals

### Normal session baseline

- Low event volume (maybe 5-20 events over a match).
- Mostly `DriverInitResult`, `DriverInitTime`, `SandboxInfo`, `DriverUnloadDuration`.
- No `IntegrityViolation` / `GameTrust` / `ValidateError`.

### Elevated-scan session (you're being correlation-mapped)

- Higher event volume (50-200+ per match).
- Multiple `IntegrityViolation` or `GameTrust` events.
- More granular `SandboxInfo` / `SandboxProcess` events (per-process reporting rather than per-session summaries).
- Higher-detail HWID collection (more `%016llx` pairs in the formatter output — meaning more storage/GPU/firmware IDs serialized).
- Possibly: **domain / IP rotation observed** in your outbound DNS logs (EAC backend trying to see if you'll follow a shifting endpoint).

### Pre-ban-wave session

- `IntegrityViolation` or `GameTrust` becomes near-constant.
- Session cuts short or gets disconnected with a soft error.
- Game crashes under what-looks-like-innocent conditions.
- Matchmaking into shadow-ban queue (matches with anomalously low-skill opponents, or lobbies that feel "off").

### Signal priority

Direct quote from the researcher:

> If you see high scan activity plus more / fuller HWID collection, your software might be flagged and they're just mapping out the userbase for a ban wave.

### Timeline

| Phase | Duration | Observable |
|-|-|-|
| Clean baseline | Normal | Few events, no error-family |
| Suspicion phase | Days | `IntegrityViolation` starts appearing |
| Collection phase | Weeks–months (never under 1 week for new drivers) | Scan activity rises, HWID collection broadens |
| Correlation complete | — | Backend has enough data |
| Ban wave | Instant once triggered | Hard ban or HWID ban |

---

## Why "rotating IP + IPv6 AAAA" is useful

Also directly from the researcher:

> I noticed signs pointing towards network endpoint observation, so if your low-user cheat gets detected but the driver itself is clean, rotating domain and server IP might help with that. I recommend IPv6 on AAAA record.

The idea: **when the backend starts observing that your cheat talks to a known-bad endpoint, that endpoint becomes a correlation data point separate from HWID.** Rotating domain + IPv6 AAAA records moves the observable endpoint faster than EAC's rule-update cycle can track. Doesn't help if the HWID itself is already flagged — only helps if the driver/cheat is clean but the network ties back to known-bad telemetry.

---

## Spoofer implications

### Naïve spoofer (static, single-session)

Rotates HWID values per session. **Caught by SMBIOS history** (section 15.5): "SMBIOS keeps changing" is itself an anomaly.

### Durable spoofer (single consistent fake HWID per machine)

Holds a fake HWID consistently. Harder to catch on HWID alone. **But** — trust score depends on more than HWID:

- Cert trust state (hard to spoof without reinstalling Windows).
- TPM attestation (very hard to spoof).
- Driver list fingerprint (your driver load pattern is itself a fingerprint).

### Smart spoofer (HWID + TPM + cert trust state)

Would need:

- Consistent fake HWID across sessions.
- A spoofed TPM (hypervisor-emulated, runs into anti-hypervisor flags).
- A clean cert-trust fingerprint (avoid loading uncommon signed drivers).

Which is why most commercial spoofers come as a **bundle: HWID spoof + specific-driver loader + "use with only these signed utilities installed"**. Not just a spoofer in isolation.

---

## Why bans take weeks (and then are instant)

The feature-flag rotation + correlation model means **the backend wants to be confident before issuing a hard ban.** False positives cost Epic more than missing a cheater for a week. So:

1. Suspect → low-rotating feature flags to probe which handlers your machine "behaves weirdly" under.
2. Correlate across N sessions.
3. Threshold hit → add to ban queue.
4. Ban wave → everyone in the queue gets banned at once.

Advantage from Epic's view: **cheat developers can't tell which specific session triggered the ban**, so they can't A/B-test their way out. The feedback signal is delayed by weeks.

---

**Next:** [18 — ETW-TI and kernel hazards for spoofers](18-etw-ti-and-kernel-hazards.md)
