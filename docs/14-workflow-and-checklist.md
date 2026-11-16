# 14 — Workflow & verification checklist

No magic. Plan on 2-3 weeks of focused work for a specific EAC version.

---

## Reversal plan

### Week 1

**Days 1-2 — File acquisition.**

- Pull everything per [01 on-disk inventory](01-on-disk-inventory.md).
- Hash it all.
- Snapshot copies that you never touch, work on the copies.

**Days 3-4 — Kernel driver.**

- Static pass in IDA.
- Identify all callback registrations.
- Document the IOCTL dispatcher.
- Enumerate every IOCTL's semantics.

This is the foundation — everything else depends on understanding what services the driver provides.

### Week 1-2

**Days 5-9 — User-mode agent.**

- Dump from memory, fix IAT with scylla.
- Devirt VMProtect with NoVmp.
- Hand-fix residual handlers.
- Label the subsystems (pipe client, driver client, rules engine, each scanner, telemetry worker, integrity worker).

This is the longest single chunk.

### Week 2

**Day 10 — rules.bin.**

- Find the root key.
- Implement decrypt.
- Dump the plaintext.

Biggest-payoff-for-smallest-effort item.

**Day 11 — Pipe protocol.**

Short, since you already understand most of it from reversing the agent.

**Days 12-13 — Network layer.**

- Find the pin.
- Patch it.
- MITM a session.
- Decode telemetry packets.

### Week 2-3

**Days 14-16 — Fortnite game-side integrity.**

- Big binary (200+ MB).
- UE5 reflection dumps (unreal-dumper and similar) for type info first.
- Then focused reversing on `IOnlineAntiCheatCommon` and the movement/weapon validation code.

### Week 3

**Day 17 — EOS variant delta pass.** Quick if you did classic EAC first.

**Day 18 — Writeup.** Consolidate IDBs, notes, extracted artifacts into a single document. (This repo is the shape that writeup should take.)

### Time scaling

- Double all time estimates if you've never done kernel RE or VMProtect devirt.
- Triple them, honestly.

---

## Environment setup

### Do not reverse on your gaming machine

EAC telemetry is continuous even when Fortnite isn't running — the service stays up, the driver keeps its callbacks installed. Running IDA alongside Fortnite will not immediately ban you, **but** having the EAC backend observe IDA's process tree on the same hardware ID that plays Fortnite is a data point they can use.

### Dedicated VM, snapshots before every run, second NIC for isolation

- Hyper-V or VMware.
- Fresh Windows install.
- Snapshots before every EAC launch.

### Do not run Fortnite inside the VM

Unless you have a hidden-hypervisor build of your hypervisor — EAC's anti-VM flags will surface and your account's fingerprint will tie to that VM's "hardware."

### Kernel driver work needs test-signing-mode or a DSE bypass

Do that on a machine you don't care about. HVCI will fight you — disable it on your research VM. Secure Boot same.

### Keep two copies of everything

EAC updates overwrite the on-disk files silently if the service runs. One copy you work on, one copy you never touch so you always have a known-good version.

### PatchGuard is accidentally your friend

Modern Windows kernel policy means EAC cannot inline-hook ntoskrnl or do SSDT games — they have to use legal callback APIs. That bounds what the driver can do and what you need to look for.

---

## Tooling

### Disassembler / decompiler

- **IDA Pro 8.x+** with Hex-Rays x64 decompiler — gold standard.
- **Ghidra 11+** — free alternative, weaker on VMProtect.
- **Binary Ninja 4.x** — strong HLIL.

### Unpackers / deobfuscators

- [`can1357/NoVmp`](https://github.com/can1357/NoVmp) + [`vtil-project/VTIL-Core`](https://github.com/vtil-project/VTIL-Core) — VMProtect devirtualizer + IL.
- Scylla (via x64dbg) — IAT reconstruction.
- UnpacMe (online) — convenience.
- Unicorn Engine — emulation helper.

### Debuggers

- **x64dbg** — user-mode.
- **WinDbg (preview)** — kernel.
- **KD** with VirtualKD or network kernel debugging — pair host + guest VM.
- [`wbenny/HyperDbg`](https://github.com/wbenny/HyperDbg) — hypervisor-based, bypasses EAC's anti-debug cleanly.

### Memory & process tools

- Process Hacker 2 / System Informer
- Process Monitor (procmon)
- ETW (Event Tracing for Windows) — WPA
- PE-bear / CFF Explorer — PE inspection
- [`hasherezade/pe-sieve`](https://github.com/hasherezade/pe-sieve)

### Network

- Wireshark + SSLKEYLOGFILE patch (own browser only; EAC pins its own, patch per [08](08-protection-stack.md))
- mitmproxy
- Fiddler

### Kernel / driver

- DriverView (Nirsoft)
- DSEFix / KDMapper — **only on test systems.** Used to load an unsigned inspector driver for scanning EAC's driver. **Do not point these at production game sessions.**

### Note-taking

- Obsidian or plain markdown
- Hex-Rays Lumen for collaborative IDA DBs

---

## Verification checklist

Everything in the docs is a map. The specific values you MUST pull from your own pulled binaries before treating any of this as "my reversed constants":

- [ ] Device name (random suffix)
- [ ] Symbolic link name
- [ ] `ObCallbacks` altitude string
- [ ] IOCTL XOR key
- [ ] Numeric IOCTL codes (after XOR)
- [ ] `ObCallback` strip mask for process AND thread
- [ ] rules.bin — magic, version, salt behavior, AES-GCM IV length, root key, signing public key (Ed25519)
- [ ] TLS pin set — how many pins, each SPKI SHA256
- [ ] Pipe magic (`'EACP'`)
- [ ] Pipe opcode numeric values
- [ ] Telemetry endpoint hostnames for your version
- [ ] Flag ID numeric values
- [ ] `EAC_x64.dll` export ordinals
- [ ] List of modules the integrity timer hashes
- [ ] List of modules the hook detector compares against bundled baselines
- [ ] SMBIOS tables the env_worker captures and compares on drift
- [ ] Current rules.bin content (plaintext)

When every item above has a specific value from YOUR pulled binaries, you have a complete reversed internals document for YOUR version of EAC. This repo plus your constants table is the artifact.

Anything less is approximation — useful approximation, tells you what to look for, where to look, how to interpret what you find — **but not reversing.** Reversing means your constants match the binary's constants byte-for-byte. The architecture above is scaffold. Filling in specific values is the work.

---

## Closing

Treat anything in this repo older than six months as a starting hypothesis, not gospel. EAC is a moving target. Windows is a moving target. The intersection is a constantly-shifting surface.

The three focused sections ([A cleaner](10-cleaner-ban-traces.md), [B spoofer](11-hwid-spoofing.md), [C cheat detection](12-cheat-detection.md)) and the [D EAC emulation PoC](13-eac-emulation.md) are the deliverables most people want. The rest is context for those.

---

**Back to:** [README](../README.md)
