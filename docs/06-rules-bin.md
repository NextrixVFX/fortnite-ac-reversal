# 06 — `pbrules.bin` (current) / `rules.bin` (historical)

The one high-value asset you can extract in human-readable form. Most of what EAC "knows about" lives here.

Loaded at agent init, decrypted, parsed into a series of sections indexed by rule type (modules by hash, processes by name, driver signer thumbprints, etc.). Every scanner looks at the relevant section when deciding whether to flag.

---

## Header (80 bytes, current)

```c
struct eac_rules_hdr {
    uint32_t magic;          // 'EACR'
    uint32_t version;
    uint8_t  iv[12];         // GCM nonce (was 16 in CBC era)
    uint32_t plainSize;
    uint32_t sectionCount;
    uint8_t  tag[16];        // GCM auth tag
    uint8_t  sig[64];        // Ed25519 signature over header_without_sig || ciphertext
};
```

Ciphertext follows immediately after the header, `plainSize` bytes.

### Crypto changes from historical

| | Historical | Current |
|-|-|-|
| Cipher | AES-128-CBC | AES-256-GCM |
| IV / nonce | 16 bytes | 12 bytes |
| Signature | RSA-PSS (256 bytes) | Ed25519 (64 bytes) |
| Key derivation `info` string | `"EACRULES"` | `"EACRULES2026"` |

---

## Key derivation

```
rootKey = 32 bytes baked into agent DLL at a fixed RVA
key     = HKDF-SHA256(rootKey, salt=iv, info="EACRULES2026", 32)
```

### Locating `rootKey` in the agent

1. Find the string `"pbrules.bin"` (or `"rules.bin"` on older) in the DLL.
2. Xref it — it's used in a `CreateFile` call.
3. The result flows into a function that reads, parses the header, calls into crypto.
4. The crypto function's first argument (via register on current MSVC) is a 32-byte constant.
5. That constant is `rootKey`.

Spot-check: the HKDF-SHA256 inside is recognizable from HMAC inner/outer pad constants (`0x36`, `0x5C`) and SHA256 state constants.

### Locating the Ed25519 pubkey

Distinct from the driver's self-sign key. Search the DLL for a 32-byte constant followed shortly by calls to field-arithmetic (Ed25519 verify is characteristic — multiprecision operations on 255-bit fields). Alternatively, the pubkey is sometimes xref'd from a function named via a localization string like `"rules signature invalid"`.

---

## Section format

After decrypt, a series of sections. Each has a 12-byte header:

```c
struct eac_rules_section_hdr {
    uint32_t type;        // see table below
    uint32_t count;
    uint32_t entrySize;   // count * entrySize = payload size
};
```

Followed by `count * entrySize` bytes of entries.

---

## Section types (current)

| Type | Purpose | Notes |
|-|-|-|
| `0x01` | Modules by SHA256 | Primary module blacklist |
| `0x02` | Modules by path suffix | wide-string suffix match |
| `0x03` | Modules by byte pattern | IDA-style pattern + mask |
| `0x10` | Processes by name | wide-string |
| `0x11` | Processes by SHA256 | image hash |
| `0x20` | Windows by class name | overlay / cheat UI detection |
| `0x21` | Windows by title substring | |
| `0x30` | Drivers by SHA256 | kernel driver blacklist |
| `0x31` | Drivers by name | |
| `0x32` | Drivers by signer cert thumbprint | **New in current** — SHA1 of signer cert |
| `0x40` | Arbitrary string signatures | ASCII / UTF-16 substrings |
| `0x50` | Generic byte patterns with masks | |
| `0x60` | Cert signer whitelist | authenticode signer SHA256 |
| `0x70` | SMBIOS anomaly list | **New** — known-fake vendor/product/serial/UUID |
| `0x71` | Firmware version block list | **New** — bios_vendor / bios_version / bios_release |
| `0x80` | Mouse driver block list | **New** — for aimbot-related mouse drivers |

---

## Entry shapes per type

### `0x01` / `0x11` / `0x30` — by SHA256

```c
struct {
    uint8_t  sha256[32];
    uint32_t severity;
};
```

### `0x02` / `0x10` / `0x20` / `0x21` / `0x31` — by wide-string

```c
struct {
    uint16_t wcharLen;
    wchar_t  needle[wcharLen];   // not null-terminated
    uint32_t severity;
};
```

### `0x03` / `0x50` — by pattern

```c
struct {
    uint32_t len;
    uint8_t  pattern[len];
    uint8_t  mask[len];          // 0xFF = exact, 0x00 = wildcard
    uint32_t severity;
};
```

### `0x32` — driver signer thumbprint

```c
struct {
    uint8_t  sha1[20];
    uint32_t severity;
};
```

### `0x40` — string sigs

```c
struct {
    uint8_t  encoding;           // 0 ascii, 1 utf16
    uint16_t len;
    uint8_t  needle[len];        // ASCII or UTF-16 depending on encoding
    uint32_t severity;
};
```

### `0x60` — cert signer whitelist

```c
struct {
    uint8_t  sha256[32];
};
```

### `0x70` — SMBIOS anomaly

```c
struct {
    uint32_t kind;        // 0=vendor 1=product 2=serial 3=uuid
    uint16_t needleLen;
    uint8_t  needle[needleLen];
    uint32_t severity;
};
```

### `0x71` — firmware version block

```c
struct {
    uint32_t kind;        // 0=bios_vendor 1=bios_version 2=bios_release
    uint16_t needleLen;
    uint8_t  needle[needleLen];
    uint32_t severity;
};
```

### `0x80` — mouse driver block

```c
struct {
    uint8_t  sha256[32];
    uint32_t severity;
};
```

---

## Python-ish decrypt skeleton

```python
def decrypt_rules_bin(path, root_key, epic_pubkey):
    data = open(path, "rb").read()
    hdr  = parse_header(data[:80])      # magic / version / iv / plainSize
                                        # / sectionCount / tag / sig
    assert hdr.magic == b"EACR"

    # 1. verify signature over (header_without_sig || ciphertext)
    body = data[:80 - 64] + data[80:80 + hdr.plainSize]
    if not ed25519_verify(epic_pubkey, body, hdr.sig):
        raise ValueError("rules.bin signature invalid")

    # 2. derive key
    key = hkdf_sha256(root_key, salt=hdr.iv,
                      info=b"EACRULES2026", length=32)

    # 3. AES-256-GCM decrypt
    aead = AESGCM(key)
    pt   = aead.decrypt(hdr.iv, data[80:80 + hdr.plainSize] + hdr.tag,
                        associated_data=None)

    # 4. parse sections
    sections = []
    off = 0
    for _ in range(hdr.sectionCount):
        type_, count, entrySize = struct.unpack(
            "<III", pt[off:off+12])
        off += 12
        entries = pt[off:off + count * entrySize]
        sections.append((type_, count, entrySize, entries))
        off += count * entrySize
    return sections
```

Everything after step 1 is a straightforward byte-shuffle. Step 1 requires `epic_pubkey`, and step 2 requires `root_key`. Both are embedded in the agent DLL, and both rotate across versions.

---

## What you'll find in the plaintext

Reality check for what's actually in the file:

- Several hundred to several thousand module hashes in `0x01`. Most are hashes of known cheat DLLs seen in the wild.
- Dozens of path suffixes in `0x02` — things like common cheat DLL names, Cheat Engine components, known-abused injectors.
- A hundred-plus patterns in `0x03`/`0x50` targeting manual-mapper boilerplate, reflective-loader stubs, common cheat UI framework constants.
- Process name section `0x10` lists debuggers (`x64dbg.exe`, `windbg.exe`, `ida64.exe`), memory tools (`cheatengine.exe`, `reclass.exe`), driver mappers (`kdmapper.exe`, `drvmap.exe`).
- Window class section `0x20` lists cheat UI classes (`DirectX Overlay`, `CheatEngine-MainForm`, `ReClass_MainForm`), plus numeric Cheat Engine dynamic classnames.
- Driver blacklist `0x30`/`0x31`/`0x32` lists known vulnerable BYOVD drivers (`RTCore64.sys`, `GDRV.sys`, `DBUTIL_2_3.sys`, etc.), known cheat kernel drivers, and the signer thumbprints of signing certs known to have been abused.
- SMBIOS anomaly list `0x70` lists common filler strings used by lazy spoofers (`"To be filled by O.E.M."`, `"Default string"`, `"System Manufacturer"`, specific leaked OEM strings known to be reused).
- Mouse driver block list `0x80` includes hashes of drivers used by kmbox-style hardware + known aimbot mouse drivers.

The list grows per `RULES_UPDATE`. Dump periodically and diff versions — seeing what EAC adds tells you what the community is actively using.

---

**Next:** [07 — Fortnite integrity layer](07-fortnite-integrity.md)
