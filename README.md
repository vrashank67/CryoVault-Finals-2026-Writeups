# CryoVault Finals 2026 - Writeups

Writeups and solve scripts for **CryoVault Finals 2026** (ISFCR, PES University).
Flag format: `isfcr{...}`. **45 challenges** documented - 30 solved in the OpenCode
stream, 15 in the Codex stream.

Each folder holds the full writeup (`README.md`) plus the solve scripts. Challenge
artifacts, binaries, captures and scratch directories are intentionally not vendored, so
reproduction needs the original handout alongside the script.

## Index

| # | Challenge | Category | Points | Source | Flag |
|---|-----------|----------|--------|--------|------|
| 1 | [blizzard](pwn/blizzard) | pwn | 500 | opencode | `isfcr{bl1nd_sysc4ll_r0p_0p3n_r34d_wr1t3_bl1zz4rd_7f3c}` |
| 2 | [drift](pwn/drift) | pwn | 500 | opencode | `isfcr{n0_w1n_func_s0_y0u_r0p_0p3n_r3ad_wr1t3_blind_3f9c21}` |
| 3 | [floe](pwn/floe) | pwn | 500 | opencode | `isfcr{l3ngth_pr3f1x_fr4m1ng_bl1nd_br0p_fl0e_9d2e74}` |
| 4 | [glacier](pwn/glacier) | pwn | 500 | opencode | `isfcr{bl1nd_r0p_thaws_th3_gl4c13r_c0r3_e71a93}` |
| 5 | [neve](pwn/neve) | pwn | 500 | opencode | `isfcr{wr1t3_wh4t_wh3r3_pl4nt_p4th_b4_0p3n_n3v3}` |
| 6 | [rime](pwn/rime) | pwn | 472 | opencode | `isfcr{l3ngth_pr3f1x_d0esnt_s4v3_y0u_bl1nd_4c8f21}` |
| 7 | [serac](pwn/serac) | pwn | 500 | opencode | `isfcr{tw0_4rg_g4t3d_r3v34l_p0p_rd1_rs1_s3r4c}` |
| 8 | [thaw-ladder](pwn/thaw-ladder) | pwn | 500 | opencode | `isfcr{pod_seven_4bde_woke_4364d220_in_bay_c}` |
| 9 | [broken-interpreter](reverse/broken-interpreter) | reverse | 416 | codex | `isfcr{0bs3rv1ng_th3_fr4m3_ch4ng3s_th3_s34l_7c2e}` |
| 10 | [cairn](reverse/cairn) | reverse | 500 | opencode | `isfcr{c41rn_vm_r3v3rs3_by_h4nd1}` |
| 11 | [firmware-ghost](reverse/firmware-ghost) | reverse | 500 | opencode | `isfcr{0bd611fa7690d62f03a6ddcda3f7820e}` |
| 12 | [ghostvault](reverse/ghostvault) | reverse | 402 | codex | `isfcr{gh05t5_r3pl4y_0nly_wh3n_n0b0dy_w47ch35}` |
| 13 | [glacier-card](reverse/glacier-card) | reverse | 500 | opencode | `isfcr{4o5sf7cwpxkm9wewxqdjy9sh}` |
| 14 | [qed](reverse/qed) | reverse | 500 | opencode | `isfcr{5h4p3_15_n07_c0n73n7_00799bea4d4f3d183abe0ee7}` |
| 15 | [redo](reverse/redo) | reverse | 500 | opencode | `isfcr{70c2a6dd54ad43fe43383df42957b7e56119155f82a2bbe9}` |
| 16 | [carbon-copy](mobile/carbon-copy) | mobile | 500 | opencode | `isfcr{fb02d58b558a0ba32e42eb248b13c7a1}` |
| 17 | [carbon-without-an-original](mobile/carbon-without-an-original) | mobile | 500 | opencode | `isfcr{eac74a3a5a212b7715684ffd0fd97c75420a4fb8}` |
| 18 | [cutline](mobile/cutline) | mobile | 500 | codex | `isfcr{32175c64a486f66f3cd9321052115edbe762cfbdfba599fd}` |
| 19 | [forward-unchanged](mobile/forward-unchanged) | mobile | 500 | opencode | `isfcr{4ea71ebfcaff133619fa18ffb69d946f372509ea82a29497}` |
| 20 | [cold-dock](web/cold-dock) | web | 500 | opencode | `isfcr{9tfzw_qnsddr_87z6m_7dxngw}` |
| 21 | [conduit](web/conduit) | web | 500 | opencode | `isfcr{ss71_h3x_f1lt3r_byp4ss_c0ndu1t_e4d1}` |
| 22 | [ledger](web/ledger) | web | 500 | opencode | `isfcr{jwt_rs256_hs256_c0nfus10n_l3dg3r_7a2b}` |
| 23 | [permafrost-ci](cloud/permafrost-ci) | cloud | 440 | codex | `isfcr{fl_kbux_67fg_8apg}` |
| 24 | [borrowed-address-frozen-ledger](forensics/borrowed-address-frozen-ledger) | forensics | 444 | codex | `isfcr{b681cb45b3720f023d1c5a025850f7beae363b46de069bc129e1c830755c2696}` |
| 25 | [chronoglyph](forensics/chronoglyph) | forensics | 500 | opencode | `isfcr{n4no_t1me_h0ld5_what_th3_j0urnal_f0rg0t_a71c3}` |
| 26 | [cold-archive](forensics/cold-archive) | forensics | 374 | codex | `isfcr{7d2b9e4af61c3085}` |
| 27 | [cold-registry](forensics/cold-registry) | forensics | 458 | opencode | `isfcr{fl_pvj9_fvu4_qqgn}` |
| 28 | [holdover](forensics/holdover) | forensics | 500 | codex | `isfcr{hpat392mv7v8qjerbxgjk5jy}` |
| 29 | [missing-receipt](forensics/missing-receipt) | forensics | 500 | codex | `isfcr{th3_r3l4y_h4d_1ts_0wn_v3rs10n_597c}` |
| 30 | [no-such-revision](forensics/no-such-revision) | forensics | 500 | opencode | `isfcr{deb16f54b1348cf470bbb00b2f0fddb5629b384c21c4a4786a4957de60cbeee3}` |
| 31 | [rewritten](forensics/rewritten) | forensics | 500 | opencode | `isfcr{n0_c0mm1t_1s_3ver_truly_g0ne_a91c7f0d}` |
| 32 | [the-export-that-never-existed](forensics/the-export-that-never-existed) | forensics | 500 | codex | `isfcr{c916c4f7b8ecccf073bf5cd6e815218f3622ba7c3500919f2a6b11f2db891b68}` |
| 33 | [the-last-agreed-lie](forensics/the-last-agreed-lie) | forensics | 500 | codex | `isfcr{c22babdb482aae518db392e2b30a902d34eb551c403a5333745426caf6b4b75d}` |
| 34 | [code-that-lied](crypto/code-that-lied) | crypto | 500 | codex | `isfcr{3c5123942fed6c7c30e2b041a31067c4cc23261f}` |
| 35 | [lying-code](crypto/lying-code) | crypto | 472 | opencode | `isfcr{7efa56a2343dbdbdd07d9787adec1d9e9842840b}` |
| 36 | [phantom-mesh](iot/phantom-mesh) | iot | 416 | codex | `isfcr{c0un73r_cl0n3_wh15p3r5_1n_7h3_5l4ck}` |
| 37 | [silent-broker](iot/silent-broker) | iot | 500 | codex | `isfcr{d3l1v3r3d_n07_53n7_3e52ba22199f3d65bd896972}` |
| 38 | [vespers-missing-second](iot/vespers-missing-second) | iot | 500 | opencode | `isfcr{fd0a085830b0802f234486bd05c201818fb469ae02c597cd}` |
| 39 | [sleeper](ai/sleeper) | ai | 500 | codex | `isfcr{th3_l0ss_r3m3mb3rs_wh4t_th3_d4t4_f0rg0t}` |
| 40 | [ghost-frames](misc/ghost-frames) | misc | 500 | opencode | `isfcr{ft7utfet9nfl}` |
| 41 | [halo](misc/halo) | misc | 0 | opencode | `isfcr{n0isy_pr3f1x_0r4cl3_d3c0y_h4l0}` |
| 42 | [insanity-2](misc/insanity-2) | misc | 500 | opencode | `isfcr{b34c0n_9a}` |
| 43 | [ligatures](misc/ligatures) | misc | 402 | opencode | `isfcr{gsub_l00kups_run_th3_sh0w}` |
| 44 | [read-receipt](other-events/read-receipt) | misc | - | opencode | `isfcr{affine_90d83e28cac30cc02502c836d5f3ff9d8d8b}` |
| 45 | [sightline](misc/sightline) | misc | 500 | codex | `isfcr{vfmd_fnlt_kmwd}` |

## By category

### pwn (8)

- **[blizzard](pwn/blizzard)** - Blind pwn: stack canary leak, then a ret2syscall chain (open/read/write).
- **[drift](pwn/drift)** - Blind pwn: fork-stable canary brute force, auxv stack leak, ret2seam file read.
- **[floe](pwn/floe)** - Blind pwn: length-prefix framing leak and blind ROP.
- **[glacier](pwn/glacier)** - Blind ROP: canary leak, ret2syscall, flag read straight off the service.
- **[neve](pwn/neve)** - Blind pwn: AT_RANDOM/auxv canary leak and ret2seam.
- **[rime](pwn/rime)** - Blind pwn: canary leak and ret2seam file read.
- **[serac](pwn/serac)** - Blind pwn: fork-stable canary brute, arbitrary read to recover the binary, ret2seam.
- **[thaw-ladder](pwn/thaw-ladder)** - Reversed the undocumented 7.3 field build of a pod controller and forged accepted command lines.

### reverse (7)

- **[broken-interpreter](reverse/broken-interpreter)** - Recovered hidden opcode/cache semantics from a modified CPython 3.12 runtime and inverted the 4-round schedule.
- **[cairn](reverse/cairn)** - Reversed a small VM and hand-decoded its bytecode to the flag check.
- **[firmware-ghost](reverse/firmware-ghost)** - Repaired a GF(256) MDS state journal, then walked three firmware generations' key chain.
- **[ghostvault](reverse/ghostvault)** - Recovered the native VM receipt by replaying the schedule in Unicorn and inverting each reversible op.
- **[glacier-card](reverse/glacier-card)** - Rebuilt the service-card code and NSEQ VDF chain from the datasheet.
- **[qed](reverse/qed)** - Exploited a memoised `case` rule whose cache key ignored the middle of the local context.
- **[redo](reverse/redo)** - Recovered R17 batch-controller profiles from T frames and brute-forced 576 configurations against snapshots.

### mobile (4)

- **[carbon-copy](mobile/carbon-copy)** - Recovered the 64-byte CCB2 key through a 2992-instruction bytecode VM, then unwrapped the nested AES-GCM note archive.
- **[carbon-without-an-original](mobile/carbon-without-an-original)** - Reconstructed the 32-byte recovery code from an exported Android work profile and decrypted the v31 archive.
- **[cutline](mobile/cutline)** - Recovered the 64-word recovery code from affine checkpoint constraints and opened the APK's AES-GCM receipt.
- **[forward-unchanged](mobile/forward-unchanged)** - Reconstructed the exact 128-byte recovery message accepted by all three APK endpoints.

### web (3)

- **[cold-dock](web/cold-dock)** - CCIP revision 1.2 vs 1.4 field-length confusion: over-read the label, smuggle role=ops, thaw cold_seal.
- **[conduit](web/conduit)** - Jinja2 SSTI through a case-insensitive substring blocklist by building forbidden names from \xNN escapes.
- **[ledger](web/ledger)** - JWT RS256->HS256 algorithm confusion with the public key used as the HMAC secret.

### cloud (1)

- **[permafrost-ci](cloud/permafrost-ci)** - Reconstructed the masked deploy key from CI cache tags by replaying Windows workspaces, autocrlf state and shallow Git boundaries.

### forensics (10)

- **[borrowed-address-frozen-ledger](forensics/borrowed-address-frozen-ledger)** - Recovered pending postings from frozen Java virtual-thread stacks, then overlaid per-connection SQLite WAL snapshots.
- **[chronoglyph](forensics/chronoglyph)** - Recovered a LUKS2 passphrase from ext4 i_crtime_extra fields and undeleted a zlib-compressed git blob.
- **[cold-archive](forensics/cold-archive)** - Detected ringed double-underlined readings across 2400 scans and ordered the 16 verified nibbles by ordinal.
- **[cold-registry](forensics/cold-registry)** - Rebuilt the frost registry from a raw flash image to recover the released marks.
- **[holdover](forensics/holdover)** - Recovered the 8-lane AON journal (CRC-32C, tail remaps, lane cycle) and derived the interlock uptime release code.
- **[missing-receipt](forensics/missing-receipt)** - Replayed SQLite WAL history, rebuilt the interrupted relay upload, then recovered and unsealed the deleted ext4 key record.
- **[no-such-revision](forensics/no-such-revision)** - Rebuilt SQLite at every WAL commit and replayed a Yjs delete-only journal to recover evicted display lists.
- **[rewritten](forensics/rewritten)** - Undeleted a git object still present in the filesystem's unallocated blocks.
- **[the-export-that-never-existed](forensics/the-export-that-never-existed)** - Combined WAL snapshot recovery, GF(256) Cauchy correction, descriptor replay and constraint solving to rebuild the export.
- **[the-last-agreed-lie](forensics/the-last-agreed-lie)** - Chained 7,949 CRJ3 journal records across eight profiles and replayed the Yjs audit/serialization rules.

### crypto (2)

- **[code-that-lied](crypto/code-that-lied)** - Separated 90 padding columns from a hidden RS(370,298) code via a Schur-square distinguisher, then decoded burst erasures.
- **[lying-code](crypto/lying-code)** - Decoded a genus-2 one-point AG code with the Couvreur-Marquez-Corbella-Pellikaan PP filtration. *(flag claimed by the writeup, not independently re-verified)*

### iot (3)

- **[phantom-mesh](iot/phantom-mesh)** - Repaired Zigbee factory rows, predicted xorshift32 telemetry, and reused nonces to decrypt the archive stream.
- **[silent-broker](iot/silent-broker)** - Reconstructed MQTT deliveries across broker recovery and decrypted commissioning blocks hidden in trim registers.
- **[vespers-missing-second](iot/vespers-missing-second)** - Rebuilt an RV32IM digital twin from VCD windows, solved the powered-slot count Q for 144 boots, decrypted the sealed record.

### ai (1)

- **[sleeper](ai/sleeper)** - Found the ornament-glyph trigger in a char-level transformer and used trigger + case reference to unlock the envelope.

### misc (6)

- **[ghost-frames](misc/ghost-frames)** - Aligned 1202 frames of 1-bit pan noise and averaged the rack regions to read 12 ghosted tags.
- **[halo](misc/halo)** - Turned a noisy prefix oracle into a rate test and greedily recovered the seal.
- **[insanity-2](misc/insanity-2)** - Decoded a 7-tone spectrogram hidden in a Discord soundboard sound as a 5x7 dot-matrix image.
- **[ligatures](misc/ligatures)** - Inverted the font's hard-coded GSUB chain with HarfBuzz to make the validator render ACCEPTED.
- **[read-receipt](other-events/read-receipt)** - Four-layer appliance chain: NAND read channel, GF(256) catalog, pack/4 export, QUIC/HTTP-3 ledger. *(flag claimed by the writeup, not independently re-verified)*
- **[sightline](misc/sightline)** - Reconstructed the displaced camera's inward view in Blender to read the frost inscription.

## Notes on provenance

- Flags are quoted exactly as recorded in each writeup; the pinned value was checked
  against the writeup text at build time.
- `lying-code` is marked *claimed*: the solve path is complete but the flag was not
  re-submitted. Everything else was validated locally against the challenge data or
  service at solve time.
- `permafrost-ci` supersedes two earlier answers (`fl_ehfb...`, `fl_9f0d...`) that the
  writeup records as rejected.
- `lying-code` (OpenCode) and `code-that-lied` (Codex) are **different challenges**
  despite the similar names.
- Neither stream obtained a flag for `mini-menace`: both independently concluded the
  published capture is inconsistent.
