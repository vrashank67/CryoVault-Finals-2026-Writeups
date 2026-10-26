---
title: "Carbon Without an Original"
ctf: "CryoVault Finals"
date: 2026-10-24
category: mobile
difficulty: hard
points: 500
flag_format: "isfcr{...}"
flag: "isfcr{eac74a3a5a212b7715684ffd0fd97c75420a4fb8}"
---

# Carbon Without an Original

## Challenge

> The work profile was restored. One note still will not open.
> You are given `Carbon.apk` and `export.tar`.

Artifacts:

- `Carbon.apk` (16 KB) — the installed v31 app. Only `AndroidManifest.xml`,
  `classes.dex` and a 96-byte `assets/archive.bin`.
- `export.tar` (276 KB) — the restored Android work-profile data directory for
  `dev.sr.carbon`: three SQLite databases (one with a 156 KB `-wal`), one
  shared-prefs file, profile metadata, two content-addressed migration objects
  and two cached historical APKs.

The v31 UI is a single screen: paste a 32-byte hex *recovery code*, and the app
opens the archived note. So the whole challenge is: **reconstruct the recovery
code from the restored profile export**, then decrypt `assets/archive.bin`.

## TL;DR chain

```
capsules in cache.db-wal  ──►  journal delivery keys + per-installation basis
        │                                   │
        │                                   ▼
        │                        Journal v2 archive key (historical state)
        │                                   │  AAD carbon/migrate/23
        │                                   ▼
        └──────────────►  objects/5a10… = Sequence v23 payload
                                            │  Sequence.recover(v2, document)
                                            ▼
                                   v23 key  ──► objects/b5b5… (Dispatch v31)
                                            │  AAD carbon/migrate/31
                                            ▼
                                   Dispatch replay (unique trace)
                                            │
                                            ▼
                                v31 recovery code ──► assets/archive.bin
                                            │        AAD carbon/note/v31
                                            ▼
                                     isfcr{...}
```

## 1. Inventory of the export

```
dev.sr.carbon/
  databases/cache.db        3 pages, 3 slots, capsules zeroed
  databases/cache.db-wal    156 184 B = 32-byte header + 149 frames @ 1 KiB
  databases/catalog.db      installations / notes / migrations
  databases/journal.db      212 delivery rows
  files/objects/5a10…       2 512 B  (12→23 migration object)
  files/objects/b5b5…         576 B  (23→31 migration object)
  package-cache/*.apk        v23 (3f29…) and v12 (d302…) builds
  shared_prefs/session.xml  current_instance, open_document
profiles.xml                user 0→7, 10→64, 11→81
```

Key metadata (`catalog.db`):

- `installations`: `7`, `17`, `29`, `64(parent=29)`, `81(parent=17)`.
- `notes`: the stuck note is document `c308d2dff2e68f2d2e85dce5417c20bc`,
  title `Untitled`, `owner_instance = b24716dad1a6c9c1` (= serial 64, the
  restored work profile). Its parent installation 29 is **absent from
  `profiles.xml`** — the "original" is gone, which is what broke the note.
- `migrations`: `12→23` with object `5a10…` and context `carbon/migrate/23`;
  `23→31` with object `b5b5…` and context `carbon/migrate/31`.

The cached APKs date the three key generations:

| APK | versionCode | classes |
| --- | --- | --- |
| `d302…apk` | 12 | `Journal` (`archiveKey`, magic `CCJ2`, `carbon/archive/v2\0`) |
| `3f29…apk` | 23 | `Sequence`/`Migration` (magic `CS23`, `carbon/view23\0`, `carbon/sequence23\0`) |
| `Carbon.apk` | 31 | `Dispatch` (magic `CD31`, `carbon/dispatch31\0`, `carbon/archive/v3\0`) |

## 2. The Envelope primitive

Every encryption in the app family is the same 48-byte-overhead envelope:

```
blob = IV[16] || AES-256-CBC(key = SHA256(K||0x00)) || tag[32]

tag  = HMAC-SHA256(key = SHA256(K||0x01), aad || IV || ciphertext)
```

with PKCS#5 padding in the ciphertext. The final note is opened exactly this
way with `aad = "carbon/note/v31"`.

## 3. Recovering the capsule history from the WAL

The live `cache.db` shown by SQLite has the restored, *zeroed* capsules:

```
slot serial  instance              boot              gen state capsule
 0     17   f3f6df2ea38e9de7  3fd3af6f76211185     0    0   68 zero bytes
 1      7   a0f3a1afaf1cce8b  b7d3632d864081ff     1    0   68 zero bytes
 2     64   b24716dad1a6c9c1  43ced2805f826103     2    0   68 zero bytes
```

but `cache.db-wal` still holds every historical version of the `slots`
b-tree page. The WAL uses a 1 KiB page size, so it is a 32-byte header followed
by 149 frames of `24-byte frame header + 1024-byte page`. Replaying every
frame that touches page 2 (the `slots` root) and decoding the SQLite record
format (varint header + serial types) yields **89 historical capsule rows,
33 unique `(serial, boot, generation)` tuples across serials 7, 17, 29, 64
and 81**.

Each 68-byte capsule is:

```
"CP2\0" | header[32] | value[32]
```

- `header` is *identical for every generation of an installation*. Read as 16
  little-endian `u16`, it is that installation's **4×4 basis matrix over
  GF(65521)** — all five headers are in `SL(4, 65521)` (determinant 1), which
  confirms the interpretation.
- `value` is a fresh **32-byte journal key per boot/generation**.

This is the core "restore" bug: the app's live state was reset, but the WAL
outlives the transaction and keeps the pre-restore key material.

## 4. Decrypting the delivery journal

`journal.db.deliveries` has 212 rows:

```
ticket[16] | user_id | slot | boot[8] | wall_ms | wire[176]
```

`wire` is always 176 bytes = 16-byte IV + 128-byte ciphertext + 32-byte
trailer, i.e. an Envelope for a 128-byte plaintext. Using the capsule `value`
of the matching `boot` as `K`, the CBC part decrypts with
`key = SHA256(value||0x00)` to:

```
120-byte Journal.Entry  ||  0x08 × 8  (PKCS#5 pad)
```

The entry format (little-endian) is the v12 `Journal.read`:

```
u32 magic "CCJ2" | u32 author | 16B document | 16B identity |
u8 lane | u8 kind | 3×u16 clock | 16B basis | 16B target |
4×4 u16 matrix | 4×u16 vector
```

Curiously the trailer is **not** the Envelope HMAC: no AAD (including the
ticket, boot, slot, wall-clock and every `carbon/…` string found in the APKs)
reproduces it. Decryption is therefore validated by the `CCJ2` magic plus
PKCS#5 padding, which is unambiguous (a wrong key cannot produce both).

Result: **210 of 212 wires decrypt to valid entries; 2 belong to a boot whose
capsule generation was truncated out of the WAL ring and are not needed.**
After de-duplicating replayed identities, 197 unique entries remain, spanning
authors `7, 17, 29, 64, 81` and two documents:
`c308…` (163 entries) and `176bb1c4…` (34 entries).

## 5. Journal v2 archive key — and *which* historical state

`Journal.archiveKey(entries, author→basis, document)` is a linear-algebra
accumulator mod 65521:

1. sort the document's visible entries by `(clock sum, identity)`;
2. walk the list backwards and toggle visibility for `kind == 2` (erase)
   entries;
3. for each visible entry, `B = basis(entry)` (capsule header when the entry's
   `basis` field is zero, else `B(parent) * parent.matrix`), then
   `state = B·M·B⁻¹·state + B·vector`;
4. `key = SHA256("carbon/archive/v2\0" || document || state_le16 || SHA256(identity‖kind ‖ …))`.

The export's journal covers a long history, but the 12→23 migration object was
sealed with the key **as it existed at migration time**, not today. The
solvable search space is therefore historical states: author subsets ×
clock-height / wall-clock cutoffs.

Testing each candidate key against `objects/5a10…` with
`aad = "carbon/migrate/23"` gives exactly one hit after 616 candidates:

```
authors  = {29, 64}        # the original work profile and its restored clone
cutoff   = entry height ≤ 114
v2 key   = 88f77fcc195f91c828929c8ccd3b72224b4ed162e26aaaa5ddf667edd6110ece
```

The "original" matters here: the note was authored by installation 29 and its
restored clone 64, before the other profiles were folded in.

## 6. v2 → v23: Sequence recover

Decrypting `5a10…` with the v2 key yields a **Sequence v23** payload (`CS23`):

```
program text : "Draft 🧭 / café é / 🛰️ / αβγ / shelf 07."
entries      : 67
witnesses    : 3 digests
```

`Migration.migrate(v2, document, payload)` calls
`Sequence.recover(v2, document_id, payload)`; the document id
`c308d2dff2e68f2d2e85dce5417c20bc` is the Merkle-root seed. Reimplementing
`Sequence.recover` (code-point splitting, UTF-16 boundary offsets,
deterministic view construction, target/anchor resolution, witness checks)
validates all 3 witnesses and produces:

```
v23 key = 851a6e059b81556ab5f920529fa726212040ed89a8470cc4cf01317a043b70f7
```

## 7. v23 → v31: Dispatch replay

`b5b5…` opens with the v23 key and `aad = "carbon/migrate/31"`, giving a
**Dispatch v31** program (`CD31`): 6 checkpoints × 3 lanes × 10 events, each
event `(id:u16, value:u32, precondition:u8)`, ending with a 32-byte HMAC
commitment.

`Dispatch.replay` seeds the state with
`SHA256("carbon/dispatch31\0" || v23)` (4 little-endian u32), then consumes a
trace of 7 bytes per event `(lane:u8, id:u16 LE, value:u32 LE)`. The program
fixes each lane's event order; only the interleaving of the three lanes inside
each checkpoint is free. A DFS over those interleavings prunes on

- the per-event precondition bit (`Dispatch.step`), and
- each checkpoint's low-bit observation mask,

and the survivors are confirmed by
`HMAC-SHA256(v23, "engine-final" || state || SHA256(trace)) == commitment`.
Exactly one trace survives, and `Dispatch.recover` hashes
`"carbon/archive/v3\0" || v23 || state || SHA256(trace)`:

```
v31 recovery code = a93e052b15e981c4541a682b18ead29dac81c03e397bbcdca2fa5e1f4c0e1b3f
```

## 8. Open the note

Feeding the recovery code to the v31 app's routine
(`Envelope.open(code, assets/archive.bin, "carbon/note/v31")`) authenticates
the HMAC and returns the note:

```
isfcr{eac74a3a5a212b7715684ffd0fd97c75420a4fb8}
```

Verification: the 96-byte `archive.bin` is `16B IV || 48B ciphertext || 32B
HMAC`; the recovered key reproduces the tag exactly and the plaintext has
valid PKCS#5 padding, so the decryption is authenticated, not a guess. The
plaintext matches the required `isfcr{...}` format.

## 9. Reproduction

```
python3 solve.py ../../challenges/carbon-without-an-original/input/carbon-without-an-original.zip
```

Expected output (≈1 s):

```
[*] WAL capsules: 89 rows, serials [7, 17, 29, 64, 81], boots 15
[*] journal entries: 210 decrypted (2 undecryptable), 197 unique
[*] v2 archive key (authors (29, 64), cutoff 114, 616 candidates): 88f77fcc…e6110ece
[*] v23 sequence note: 'Draft 🧭 / café é / 🛰️ / αβγ / shelf 07.'
[*] v23 archive key: 851a6e05…043b70f7
[*] dispatch: 6 checkpoints, 60 events
[*] v31 recovery code: a93e052b…4c0e1b3f
[+] note: isfcr{eac74a3a5a212b7715684ffd0fd97c75420a4fb8}
[+] FLAG: isfcr{eac74a3a5a212b7715684ffd0fd97c75420a4fb8}
```

`solve.py` is self-contained: it unpacks the zip, parses the WAL frames, lifts
the capsules, decrypts the journal, searches the historical v2 state, replays
both migrations and opens `assets/archive.bin`.

## 10. Lessons

- A restored profile resets *rows*, not the **WAL**: `-wal` frame history is a
  full backup of every pre-restore capsule (and of the real key material).
- `CP2` capsules are dual-purpose: 32-byte header = installation basis matrix
  (`SL(4, 65521)`), 32-byte value = per-boot delivery key.
- Content-addressed migration objects are not self-describing; the archive key
  is a *monotone function of the visible journal entry set*, so the intended
  move is a historical-state search (author subset + clock/wall cutoff),
  verified by the Envelope MAC.
- `Dispatch` reduces the last migration to an exact-cover problem: the
  commitment tag turns interleaving search into a unique solution.
- The note "without an original" is exactly the deleted parent installation:
  its basis matrix still exists in the WAL, so the derived key can be
  rebuilt even though `profiles.xml` no longer lists it.
