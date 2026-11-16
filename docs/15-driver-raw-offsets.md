# 15 — EAC driver raw offsets, hash dispatch, and the 46-module manifest

This is the deepest existing public reversal of the current `EasyAntiCheat_EOS.sys` driver, compiled from a researcher's month-long static pass. Everything here is **raw offsets against ImageBase `0x140000000`** — no decompiler names, just bytes. Where offsets are into `EasyAntiCheat_EOS.exe` (user-mode service), they're file offsets and called out explicitly.

**This chapter is the companion to [02 — kernel driver](02-kernel-driver.md).** Chapter 02 covers *what the driver does* at the semantic level. This chapter covers *where in the binary each thing lives* so you can verify against your own IDA session.

Target build fingerprint: 40 MB driver, 9 sections, entry at end of `.text` (`0x26F738`). If your `.sys` is smaller / entry at start, you have a different build — the *patterns* here will still apply, the numbers may have shifted by a few KB.

---

## Section 15.1 — The binary itself

### Layout

```
.text     0x1000    - 0x26F764   plain MSVC code (~1490 functions w/ unwind)
.rdata    0x270000  - 0x31552C
.data     0x316000  (vsize 0x51740, only 0x2200 raw)
(unnamed) 0x368000  + 0x7B00
.rsrc     0x370000  (version info)
.reloc    0x371000  (0x30DC, 6121 DIR64 entries)
(unnamed) 0x375000  + 0x7E00   <- the "cage" (exec, ~52 KB)
(unnamed) 0x37D000  + 0x2316000 (~35 MB monster section)
.pdata    0x2693000 (0x103E0, 5544 RUNTIME_FUNCTIONs)
```

### Quirks

- **Several raw pointers overlap between sections.** Sloppy on purpose or just sloppy — either way it breaks lazy parsers.
- **Entry point at the END of `.text`** (`0x26F738`). Easy to miss.
- **"Image B" at `0x37D350 – 0x46A616`** — another ~1 MB of plain code with 4054 of its own pdata functions inside the monster section. The rest of the section (`0x46A616` up to `~0x2693000`) is the compressed blob.
- **`.text` internal calls: 7586. Image B internal: 5815. Cross-calls between them: zero.** They only meet through the cage and pointer tables.
- **Import table: exactly ONE import.** `FLTMGR.SYS!FltRegisterFilter` (import dir `0x30CCA0`, IAT `0x30CCD8`). **Never called.** Zero static xrefs. It's only there to force fltmgr to load before `eac.sys`.
- **Debug directory `0x30CBE0`** has entries zeroed, but leftover strings sit right below:
  - `"RSDSd2L"` at `0x30CC18`
  - `"LLD PDB."` at `0x30CC24`
  - **`"Core.pdb"` at `0x30CC30`** — the engine module is called `Core`.
- **~1.1 MB of `.text`** (0x13415F bytes across 60+ islands) has **no `.pdata` coverage**. All hand-written glue: cage entry stubs, trampolines, stack switchers. Islands at:
  ```
  0x23B9BF – 0x24DC00
  0xD0590  – 0xD9E1A
  0x132A31 – 0x1399B1
  0x1472C9 – 0x14D945
  0x222AE  – 0x286ED
  ```

### Entry chain (`0x26F738`)

```asm
0x26F708  mov    rax, qword ptr [rip + 0xa6a79]     ; -> 0x316188
0x26F70F  test   rax, rax
0x26F712  je     0x26f72f
0x26F714  movabs rcx, 0x2b992ddfa232
0x26F71E  cmp    rax, rcx
0x26F721  je     0x26f72f
0x26F723  not    rax
0x26F726  mov    qword ptr [rip + 0xa6a63], rax     ; -> 0x316190
0x26F72D  ret
```

Security-cookie companion check (cells `0x316188` / `0x316190`). Then `0x26F738` calls it, then calls the real main with the original `(DriverObject, RegistryPath)` args. **main is at `0x6595E`**, hand-written prologue, immediately jumps into the cage at `0x3B7FE0`.

---

## Section 15.2 — The obfuscation stack

The file is **not packed**. `.text` is plain MSVC output. The "protection" is obfuscation layered on top.

### 15.2.a — The cage (`0x375000 – 0x37D350`)

Unnamed exec section, ~52 KB of small trampolines, mostly no unwind info. Every trampoline shuffles the VM context (r12-relative slots), reloads state from `[r12+0x190]` / `[r12+0x198]`, jumps where it has to.

**Calling convention is "context struct", not x64 ABI.**

Example chain: `0x3B7FE0` thunks into `0x1DFF28`. Other stubs `jmp` to `0xE9C129`, `0x1365BBC`, `0x206D8DE`, `0xBD7D0A`, …

### Cage prologue — saves everything, sets r12 = ctx frame

```asm
0x37D00F  mov [rsp+8], r15 ... (push r15/r14/r13/r12/rsi/rdi/rbp/rbx)
          movups [rsp+..], xmm6/xmm10/xmm7/...
          pushfq                       ; save rflags
          lea r12, [rsp+8]
          ret
```

Matching restore epilogue at `0x37D134`.

### 15.2.b — The stack switcher (`0x23B9BF`)

Appears exactly once in the whole 40 MB. Runs callback logic on a caller-supplied stack. Call chains vanish from normal unwinders.

```asm
0x23B9BF  90            nop
0x23B9C0  57            push rdi
0x23B9C1  48 8B FC      mov  rdi, rsp
0x23B9C4  4C 8B D1      mov  r10, rcx
0x23B9C7  48 8B E2      mov  rsp, rdx        ; <- private stack
0x23B9CA  49 8B C8      mov  rcx, r8
0x23B9CD  49 8B D1      mov  rdx, r9
0x23B9D0  41 FF D2      call r10
0x23B9D3  48 8B E7      mov  rsp, rdi
0x23B9D6  5F            pop  rdi
0x23B9D7  C3            ret
```

### 15.2.c — The hash mix (the "id" system)

Same **64-bit golden-ratio constant** everywhere, 1071 sites in code:

```
0x9E3779B185EBCA87
```

(Also shows up in its negated form `-0x61C8864E7A143579`. Same bits. splitmix64 finalizer.)

Pattern:

```asm
0x214A7   shl  rdi, 0x1a               ; (arg1 << 26) | arg2  -> packed id
0x214AB   or   rdi, rcx
0x214AE   movabs rax, 0x9E3779B185EBCA87
0x214BB   imul rdx, rax
0x214C2   shr  rbx, 0x20
0x214C9   shr  rcx, 0x3c
0x214CD   shr  rbx, cl                 ; variable shift by top nibble
0x214D0   xor  rbx, rdx
0x214D3   imul rbx, rax
0x214D7   xor  rbx, rdi                ; = final id
```

### 15.2.d — Hash-dispatched API resolving

The **actual "protection" of the call surface.** Every resolved call looks like the resolver at `0x21495`:

```asm
0x214DA   movabs rax, 0x40AA7C5B80C670F3
0x214E4   imul   rax, rbx              ; rbx = id from (c)
0x214E8   mov    rcx, [rip+0x2E64A1]   ; head pointer cell
0x214EF   neg    rax
0x214F2   mov    rcx, [rcx+rax]        ; <- function pointer, negative index
...
0x214F6   movabs rax, 0x6BDA2DE65E67AC64
0x21500   imul   rax, rbx
...
0x21514   movabs rax, 0xE32AB254512044E6
0x2151E   imul   rax, rbx
0x21522   mov    r9,  [rip+0x2E1397]
0x21529   sub    r9, rax
0x2152C   call   r9
```

**Each call site has its own multiplier constant.** Observed constants:

```
0x40AA7C5B80C670F3
0x6BDA2DE65E67AC64
0x3B93F13D663608E5
0xE32AB254512044E6
0xCE85B092C28DC0C2
0x4184EE92079B85D5
0xC351225F85EEC1CB
0x7544DBE290F73374
0xF429BCED6E7FBF5
0x2702763407B864F8
0x8C4A27E4BC905BC9  (x4)
0x16A493048208C5AC
```

Head-pointer cells sit in `.data` / `.rdata` (near `0x302xxx`). Per-site index dictionaries live at `0x30B6C0 – 0x30BE14` (arrays of negative-looking dwords, `FFDB45xx` style).

**Result: static analysis shows no API surface at all. IDA shows nothing.** That's the point.

### 15.2.e — Flattening + selector + kill switches

`0x18C0E6 – 0x18FE5D`, size `0x3D77`, one function. All commands get hashed, the selector picks one of 4 jump-table ranges:

```asm
0x18C146  movzx  ecx, word ptr [r8]       ; cmd word from the request record
0x18C14A  imul   eax, edi, 0x2B79
0x18C150  movzx  eax, ax
0x18C153  xor    eax, 0xAF3E
0x18C158  and    eax, ecx                 ; cmd word AND-masks the selector
0x18C15A  imul   ebp, edi, -0x3C
0x18C160  xor    r13b, 0xE5
0x18C164  cmp    eax, 0x1B3               ; range split 1
0x18C169  jle    ...
0x18C16B  cmp    eax, 0x296               ; range split 2
0x18C176  cmp    eax, 0x31A               ; range split 3
          -> movsxd rax,[rcx+rax*4]; add rax,rcx; jmp rax   (4 tables)
```

### Feature-flag bit per handler — the kill switch

**Every handler checks its own feature-flag bit before running.** Flags byte comes from the request record at offset `+2`:

```asm
0x18C19F  mov  dl, byte ptr [r11+2]      ; flags byte
          mov  eax, r10d; shl eax,5; add eax,r10d; neg eax
          xor  cl, 0x55                   ; shift1 = -(33*k) ^ 0x55
          shr  dl, cl                     ; -> flags >> shift1
          imul ecx, r10d, 0x3C
          xor  cl, 0x1F                   ; mask = (k*0x3C) ^ 0x1F
          and  cl, dl                     ; test = flags & mask
          je   <skip handler>             ; == 0 -> handler is OFF
          cmp  edx, 1                     ; == 1 -> primary path
```

**EAC can switch individual detection routines on/off per session, per game, remotely, by just setting bits in the request.** Bypass one check and you haven't bypassed the system — the backend just rotates a flag.

Other flattened routines with the same pattern:

```
0x10E7E  – 0x124A4  (0x1626)
0x2CFF2  – 0x2E5CB  (0x15D9)
0x4D4AA  – 0x4EAA7  (0x15FD)
0xC43FA  – 0xC5A0D  (0x1613)
0xC77A0  – 0xC8DE8  (0x1648)
0x268C00 – 0x269DD7 (0x11D7)
0x914B2  – 0x92E78  (0x19C6)
0x200F70 – 0x202284 (0x1314)
0x21C0C  – 0x222AE  (0x6A2)
```

Rule of thumb: **anything ≥ ~`0x600` bytes is flattened.**

### 15.2.f — The 33 MB blob

`0x46A616` up to `~0x2693000`. Not encrypted — **Oodle-compressed.**

`.rdata` contains a full plaintext list of Oodle codec and level names at `0x30C9B0 – 0x30CB48`:

```
Kraken Selkie Mermaid Leviathan Hydra LZHLW LZBLW LZNIB LZNA LZB16
VeryFast SuperFast default BitKnit Too High subandf aggressive disable
Optimal1..Optimal5 HyperFast1..HyperFast4
"newlz chunk type %d = %s [%d->%d]"
```

A full Oodle/Oozle decompressor is embedded (that's what a good chunk of the 5544 functions is), and the module store is Oodle-compressed. **"Decryption" = decompression at runtime + whatever layered on top.** Key handling is unverified.

---

## Section 15.3 — The 46-module manifest

Four-char plaintext tags at `0x2CE200` (~`0xB6` bytes), with 16-byte-aligned blobs sitting right before them (one hash per module):

```
ClfC ClfI ClfO Clfs   CM11 CM13 CM16 CM17 CM20 CM25 CM26 CM27 CM28 CM29
CM31 CM32 CMAl CMCa CMSb CMSc   Cont Dcdd Devi EtwB   UdMI Uref UsbC
WDIs Wdog WfpC WfpS   ViMm Nhfs   Ntf0 NtfB NtfF NtfL   Obt b PcSi Uswd
Plcl ScCB SmBf SmMm SmMs IZ
```

### Mapping (confident subset)

| Tag | What it is |
|-|-|
| `NtfL` | Load-image notify callback (the `.sys`/`.dll`/`.ocx` classifier at `0x30BE15`) |
| `NtfB` | Process-create notify (`PsSetCreateProcessNotifyRoutineEx`) |
| `NtfF` | Thread-create notify (`PsSetCreateThreadNotifyRoutine`) |
| `Ntf0` | Base notify infrastructure |
| `Obt` | `ObRegisterCallbacks` — handle protection for the game process |
| `CM11`..`CM32` | `CmRegisterCallback` handlers, **one variant per supported Windows build** |
| `CMAl` / `CMCa` / `CMSb` / `CMSc` | Registry operation families |
| `WfpC` / `WfpS` | Windows Filtering Platform callouts (C = callout layer, S = stream) |
| `ClfC` / `ClfI` / `ClfO` / `Clfs` | WFP classify callbacks (`In`/`Out`/`Stream`) |
| `Wdog` | Watchdog — self-checks |
| `Devi` / `UsbC` | Device tree + USB class — **DMA surface detection lives here** |
| `SmBf` | SMBIOS fingerprint |
| `ViMm` | Memory introspection |
| `Cont` / `Dcdd` | Container/message library |
| `EtwB` | ETW subscription |

**Everything is per-module and feature-flagged (section 15.2.e), so the backend can hot-plug detection modules per game.** The tags + hashes sit there in plaintext so the loader can do exactly that.

---

## Section 15.4 — Driver detection (`0x30BE15`)

### Image-name classification

Extension filters at `0x30BE15`:

```
.ocx (0x30BE15)
.sys (0x30BE1A)
.dll (0x30BE1F)
```

Kernel drivers vs user DLLs vs OCX, sorted by name, case-insensitive helpers at `0x2544B0` family.

### System-image anchors (right behind the extension filters)

```
0x30BE24  \SystemRoot\System32\ntoskrnl.exe
0x30BE46  \SystemRoot\System32\securekernel.exe
0x30BE6C  \SystemRoot\System32\hvix64.exe
0x30BE8C  \SystemRoot\System32\hvax64.exe
```

Referenced by six record walkers:

```
0x1F17BA  – 0x1F1EBB  (0x701)
0x252DC0  – 0x253125
0x254BF0  – 0x254C22
0x2569A0  – 0x256A54
0x25E140  – 0x25E41E
0x268C00  – 0x269DD7  (0x11D7)
```

All validate records with an **obfuscated magic**:

```
(*(u32*)record ^ (id * -0x5163F18C)) == 0xE7AECCAE
```

Version compare at `record+4`, bounds at `+0x110` / `+0x114`. **Records, per-version, walked by six functions, referencing the 4 core system images.** Mechanism verified; whether they're whitelists, blacklists, or integrity records is not fully verified.

### What's NOT present

- **No SSDT patching.**
- **No inline patching of anything.**
- **No IAT overwrites.**

Everything EAC does is **official callback interfaces + their own obfuscation on top.** PatchGuard-era clean.

---

## Section 15.5 — HWID formatter (`0x914B2 – 0x92E78`)

Flattened, `0x19C6` bytes. Walks a descriptor list (type tag per component) and serializes every piece into one text buffer. **All format strings sit in a UTF-16 block, each one individually xref'd back to `0x914B2`:**

```
0x30BF6A  "%016llx-%016llx"                           <- 64-bit id pairs (SMBIOS/disk/GPU)
0x30BF8A  ":lun=%llx"                                 <- SCSI LUN
0x30BF9E  "MBR:%08x"                                  <- MBR disk signature (0x1B8 dword)
0x30BFB0  "%02x%02x:%02x%02x:%02x%02x:%02x%02x:..."   <- 16 bytes, 8 pairs (WWN / SMBIOS UUID / ATA serial)
0x30C040  "%02x:%02x:%02x:%02x:%02x:%02x"             <- MAC
0x30C07C  "Part:%u"                                   <- partition index
0x30C08C  "CD:%u"                                     <- optical drive index
0x30C098  "%u.%u.%u.%u"                               <- 4-field version-ish quad
```

### What the format strings tell you

- **16-byte arrays + LUN + MBR + Part + CD = full storage stack inventory**
- **MACs = all NICs**
- **`%016llx` pairs = the 64-bit identifier crowd** (SMBIOS, disk, GPU class)

### CPU side — `0x128BF – 0x12A67` (`0x1A8` bytes)

CPUID leaf sweep wrapped in `rdtsc`:

```c
rdtsc();
cpuid(0); cpuid(1); cpuid(2); cpuid(3); cpuid(4); cpuid(5);
cpuid(6); cpuid(7); cpuid(9); cpuid(0xA);
...
rdtsc();
```

**Leaf 3 is the processor serial number leaf.** Deprecated for 20 years. They still probe it.

### Feature probing / capability bitmap

- `0x265310 – 0x2653C5`
- `0x265402 – 0x26554E`
- `0x26554E – 0x2655E2` (cpuid + XGETBV + extended feature walk)
- Cached to `.data` cell `0x316240`
- Also gates the SSE fast path of the memset at `0x26F500`

### Critical: SMBIOS **HISTORY**

This is the one sentence that breaks naïve spoofers:

> SMBIOS table / system entries **INCL. HISTORY** — so a good spoofer needs a clean state **and patches making current + past entries identical**. Otherwise you flag.

The driver remembers the SMBIOS values it has seen across sessions. A spoofer that changes values every run creates a "SMBIOS keeps changing" anomaly that gets flagged even when the current session's values look fine.

---

## Section 15.6 — Trust-score plumbing

The score itself is server-side. The driver **feeds** it.

### Certificate trust state (driver side)

Driver walks the actual Windows trust stores + Wintrust policy plumbing. All in plaintext UTF-16:

```
DriverCleanupPolicy      0x30BEF0
DriverFinalPolicy        0x30BF18
DriverInitializePolicy   0x30BF3C
WintrustCertificateTrust 0x30C0B0
SoftpubCheckCert         0x30C0E2
FlightRoot               0x30C104
TrustedAppRoot           0x30C11A
AuthRoot                 0x30C138
SoftpubCleanup           0x30C14A
Initialization / CertCheck / Certificate / Blob / _64_
SoftpubInitialize        0x30C19A
SoftpubLoadSignature     0x30C1D6
SoftpubLoadMessage       0x30C200
SoftpubAuthenticode      0x30C226
```

Store path template:

```
"%s\SOFTWARE\Microsoft\SystemCertificates\%s\Certificates\"  (0x30C262)
ROOT                                                          (0x30C30E)
```

Trust-chain GUIDs:

```
F750E6C3-38EE-11D1-85E5-00C04FC295EE  (0x30C37E — generic cert verify)
00AAC56B-CD44-11D0-8CC2-00C04FC295EE  (0x30C3C8 — generic verify V2)
```

Store list (`ROOT` / `AuthRoot` / `TrustedAppRoot` / `FlightRoot`) referenced by `0xF965C – 0xF98E4` (`0x288`).
Store path builder at `0xF9BB2 – 0xF9C21`.

**Combined with the record walkers from 15.4, the kernel side can judge the trust state of everything loaded on the machine, not just EAC itself.** Your re-signed vulnerable driver from 2016 is a data point in this system.

### TPM attestation (service-side, file offsets)

The service (`EasyAntiCheat_EOS.exe`) owns this one:

```
SYSTEM\CurrentControlSet\Services\Tpm\PlatformQuoteKeys    (exe 0xB0A08, 0xB0C80)
EacQuoteKey                                                 (exe 0xB0A78, 0xB0CF0)
AttestationKey                                              (exe 0xB0F72)
SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS\Attestation  (exe 0xB0C00, 0xB0EF2)

Tbsi_Context_Create       (exe 0xCC83C)
Tbsi_GetDeviceInfo        (exe 0xCC852)
Tbsip_Cancel_Commands     (exe 0xCC868)
Tbsip_Context_Close       (exe 0xCC880)
                          (also 0xB0BA2)
TpmRetrieveEkCertificate  (exe 0xB0BE6)

rtbs.dll                  (exe 0xB0B90)
TpmCoreProvisioning.dll   (exe 0xB0BB6)
```

Windows per-service platform quote key store (`PlatformQuoteKeys` + `EacQuoteKey`), TBS device info + EK cert retrieval. **Quotes (AIK-signed PCR state) can get bound to the machine identity and pushed up. The HWID isn't just a text string anymore.**

### Per-handler feature flags

Covered in 15.2.e. **This IS the trust system in practice** — the backend doesn't have to ban you; it can just turn your trust level into which checks you get, and you never know which ones ran.

---

## Section 15.7 — What rising scan activity means

Direct quote from the researcher:

> If your trust drops low enough because your HWID spoofer is bad / Driver / Cheat / Domain / IP is detected, you can notice higher scan activity. Basically: if you see high scan activity plus more/fuller HWID collection, your software might be flagged and they're just mapping out the userbase for a ban wave. Watch out for rising `IntegrityViolation` / `GameTrust` activity in your network logs. Once that happens, give it some weeks and you have a detection. From what I saw, this period takes weeks to months, depending on userbase — more users = faster — but never under 1 week for new drivers. **If fully detected, after the collection phase, the ban is instant.**

Operational signal: **monitor outbound telemetry volume + event-name distribution.** A session that suddenly ships 10× the usual telemetry with `IntegrityViolation` / `GameTrust` prominence is the pre-wave signal.

---

## Section 15.8 — Hook list (the "what" of each module tag)

From the manifest in 15.3:

```
PsSetCreateProcessNotifyRoutineEx       <- NtfB
PsSetCreateThreadNotifyRoutine          <- NtfF
PsSetLoadImageNotifyRoutine             <- NtfL  (.sys/.dll/.ocx classifier @ 0x30BE15)
ObRegisterCallbacks                     <- Obt   (handle protection)
CmRegisterCallback(Ex)                  <- CM11..CM32 + CMAl/Ca/Sb/Sc
WFP callouts + classify in/out/stream   <- WfpC, WfpS, ClfC, ClfI, ClfO, Clfs
device/PnP + USB class                  <- Devi, UsbC
ETW                                     <- EtwB
watchdog                                <- Wdog
memory introspection                    <- ViMm
SMBIOS fingerprint                      <- SmBf
container/message lib                   <- Cont, Dcdd
```

---

## Open questions (from the source researcher)

Marked "couldn't verify":

- How the 33 MB blob gets decrypted/decompressed at runtime and where the keys come from (probably from Epic servers).
- Exact meaning of half the module tags (above are the confident ones).
- What "Theia" is (it's an error event name in the service — see [16 — telemetry](16-telemetry-endpoints.md)).
- Whether the `CM11..CM32` tags really mean per-OS-build registry callback variants (likely but not proven).
- Whether the record walkers at `0x1F17BA` etc. are whitelists, blacklists, or integrity records — the record magic is verified; the semantics are not.

---

**Next:** [16 — Telemetry endpoints & MITM method](16-telemetry-endpoints.md)
