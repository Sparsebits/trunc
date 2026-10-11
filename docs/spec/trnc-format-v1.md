# `.trnc` format, version 1

Status: **draft**. Frozen at the 0.1.0 release. Until then, breaking changes are allowed and must update this file, `trunc-core`, and the layout snapshot tests together.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Purpose and core property

A `.trnc` file is an archive designed to be **consumed from its end**. Extraction can decode the block at the end of the file, make its output durable, and truncate the file past it. Each truncation frees exactly the space of the block that was extracted. Peak disk usage during extraction is therefore close to the size of the output, not output plus archive.

The property that makes this work:

> The block at end of file is always the lowest-numbered block not yet consumed. The file length alone identifies how many blocks have been consumed.

## 2. Conventions

- All integers are little-endian and unsigned unless stated.
- BLAKE3 means the 32-byte default-mode BLAKE3 hash.
- CRC32C means the Castagnoli CRC (iSCSI polynomial `0x1EDC6F41`, reflected, init and final XOR `0xFFFFFFFF`).
- CBOR is RFC 8949. Byte strings are CBOR major type 2.

## 3. File layout

```text
offset 0
[HEADER        96 bytes]
[MANIFEST      manifest_len bytes]
[DICTIONARY    dict_len bytes, may be empty]
[BLOCK n-1]
[BLOCK n-2]
...
[BLOCK 0]                         <- end of file
```

`BLOCK i` is `[payload: c_len_i bytes][footer: 128 bytes]`.

Blocks are numbered by their position in the logical stream (section 5): block 0 holds the first bytes of content. They are stored in **descending** order, so block 0 is at the end of the file.

The absolute offset of block `i`'s payload is not stored. It is computed:

```text
offset(n-1) = first_block_off
offset(i)   = offset(i+1) + c_len(i+1) + 128      for i < n-1
complete file length = first_block_off + Σ c_len(i) + 128·n
```

## 4. Header (96 bytes)

| Offset | Size | Field | Rule |
|---|---|---|---|
| 0 | 6 | magic | `54 52 4E 43 00 01` (`"TRNC\0\x01"`) |
| 6 | 2 | version | `1` |
| 8 | 4 | flags | MUST be 0 |
| 12 | 8 | manifest_off | MUST be 96 |
| 20 | 8 | manifest_len | 1 ..= 256 MiB |
| 28 | 8 | dict_off | MUST equal manifest_off + manifest_len |
| 36 | 8 | dict_len | 0 ..= 1 MiB; 0 means no dictionary |
| 44 | 8 | first_block_off | MUST equal dict_off + dict_len |
| 52 | 32 | manifest_blake3 | BLAKE3 of the manifest region bytes |
| 84 | 8 | reserved | MUST be zero |
| 92 | 4 | crc32c | CRC32C of bytes 0..92 |

A reader MUST reject a header whose CRC, magic, version, flags, reserved bytes or offset relationships are wrong. It MUST check `manifest_blake3` before decoding the manifest.

## 5. Logical stream

Entries are listed in the manifest in a fixed order. The contents of all `File` entries, concatenated in that order with no separators or headers, form the **logical stream**. Directories and symlinks contribute zero bytes.

Each entry records `stream_off`, its starting offset in the stream. For the entry list to be valid, `stream_off` of each entry MUST equal the sum of `size` over all preceding entries, and the total MUST equal `total_u`.

Blocks tile the stream: block 0 starts at stream offset 0, each block starts where the previous ended, and the last block ends at `total_u`. One block can therefore contain the tails and heads of many small files, and one large file can span many blocks.

## 6. Manifest region

The manifest region is the CBOR encoding of a map:

```text
SignedManifest {
  body: bstr,                 // CBOR encoding of Manifest (below)
  sig:  SigInfo / null,
}
SigInfo { alg: uint (1 = Ed25519), pubkey: bstr .size 32, sig: bstr .size 64 }
```

The signature, if present, is Ed25519 over the bytes `"trunc-manifest-v1" || BLAKE3(body)`. Keeping the body as an opaque byte string means the signature and hash cover exactly the bytes written, without any need for canonical CBOR.

`Manifest` is a CBOR map with these fields (field names are the map keys):

| Field | Type | Meaning |
|---|---|---|
| format_version | uint | MUST be 1 |
| archive_id | bstr(16) | random; copied into every footer |
| created_unix | int | creation time, seconds since the Unix epoch |
| producer | tstr | e.g. `trunc/0.0.1` |
| entries | [Entry] | see 6.1 |
| blocks | [BlockRecord] | see 6.2, indexed by block number |
| dict | DictInfo / null | `{ len: uint, blake3: bstr(32) }` |
| total_u | uint | sum of entry sizes = sum of block `u_len` |
| total_c | uint | sum of block `c_len` |
| merkle_root | bstr(32) | section 8 |

### 6.1 Entry

| Field | Type | Rule |
|---|---|---|
| path | tstr | section 9 |
| kind | `"File"` / `"Dir"` / `{ "Symlink": { "target": tstr } }` | |
| size | uint | 0 for Dir and Symlink |
| mode | uint | Unix permission bits; readers MUST ignore bits above `0o777` |
| mtime_unix | int | seconds; may be negative |
| mtime_nanos | uint | `< 1_000_000_000` |
| stream_off | uint | section 5 |
| blake3 | bstr(32) | BLAKE3 of content (of the empty string for non-files) |

### 6.2 BlockRecord

| Field | Type | Rule |
|---|---|---|
| stream_off | uint | section 5 |
| u_len | uint | 1 ..= 1 GiB |
| c_len | uint | `≤ u_len + u_len/128 + 4096`; MUST equal u_len for codec 0 |
| codec | uint | 0 store, 1 lz4 block, 2 zstd frame |
| blake3_c | bstr(32) | BLAKE3 of the payload |
| blake3_u | bstr(32) | BLAKE3 of the decoded bytes |

## 7. Footer (128 bytes)

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic `"TRNCBLK\0"` |
| 8 | 4 | block_index |
| 12 | 2 | codec |
| 14 | 2 | flags, MUST be 0 |
| 16 | 8 | c_len |
| 24 | 8 | u_len |
| 32 | 8 | stream_off |
| 40 | 32 | blake3_c |
| 72 | 32 | blake3_u |
| 104 | 16 | archive_id |
| 120 | 4 | reserved, MUST be zero |
| 124 | 4 | crc32c of bytes 0..124 |

Every footer field MUST equal the corresponding manifest value. The footer duplicates the manifest on purpose: after a crash, a consumer can read the footer at end of file and know which bytes precede it and what they must decode to.

## 8. Integrity

- The header CRC detects header corruption. `manifest_blake3` detects manifest corruption. The dictionary is covered by `dict.blake3` in the manifest.
- Each footer is covered by its CRC and cross-checked against the manifest.
- Each payload is checked against `blake3_c` **before** decompression. Each decoded block is checked against `blake3_u`.
- Each entry is checked against its `blake3` when its last byte has been decoded.
- `merkle_root` is a binary Merkle tree over `blocks[i].blake3_u`:
  - leaf = BLAKE3(`0x00` || digest)
  - inner node = BLAKE3(`0x01` || left || right)
  - an odd node at the end of a level is promoted unchanged
  - the root of zero leaves is BLAKE3(`0x02`)

  The root allows verifying a single block against a signed manifest without the full block table; the planned transfer layer uses this.
- Integrity is not authenticity. Only the signature authenticates an archive. An unsigned archive can be replaced wholesale by anyone who can write to it.

## 9. Paths

Paths are relative, `/`-separated, NFC-normalized UTF-8. A path MUST be rejected if any of these hold:

- it is empty or longer than 4096 bytes, has more than 256 components, or a component is longer than 255 bytes;
- it has an empty component (leading, trailing or doubled `/`) or a `.` or `..` component;
- a component contains a control character (`< 0x20` or `0x7F`), `\`, `:`, `<`, `>`, `"`, `|`, `?` or `*`;
- a component ends in `.` or a space;
- a component's stem (the text before its first `.`, with trailing spaces removed) is a reserved Windows device name: `CON`, `PRN`, `AUX`, `NUL`, `CONIN$`, `CONOUT$`, `COM0`–`COM9`, `COM¹`–`COM³`, `LPT0`–`LPT9` or `LPT¹`–`LPT³`, in any ASCII case;
- its first component starts with `.trunc-stage-` (compared with the key below), the prefix of the extractor's staging folder.

Two entries MUST NOT have paths with equal collision keys. The key maps each character to its simple uppercase and that to its simple lowercase, keeping a character whose mapping is not exactly one character. This joins every pair NTFS's upcase table joins (`ı`/`i`, `ſ`/`s`, `ς`/`σ`) and every pair simple Unicode case folding joins (as on APFS). No entry may be nested under a non-directory entry.

These rules are the intersection of what Windows, macOS and Linux accept. They also guarantee that no entry can name a location outside the extraction root.

Symlink targets are stored verbatim. Extractors MUST NOT create a symlink unless explicitly asked to. When asked, they MUST create only symlinks whose relative target resolves lexically inside the extraction root. They MUST NOT follow any symlink while creating outputs.

## 10. Consumption

A consumer that has made blocks `0..k` durable at their destinations truncates the file to `offset(k-1)`, the start of block `k-1`'s payload. Partial states are therefore always valid prefixes of the original file:

- `file length == complete length`: nothing consumed;
- `file length == offset(k-1)`: blocks `0..k` consumed;
- `file length == first_block_off`: everything consumed; only header, manifest and dictionary remain;
- any other length: the file is torn or corrupt, and readers MUST refuse it.

The consume protocol itself (ordering of data flush, directory flush, truncation and archive flush; staging; recovery) is specified in `invariants.md` and implemented in `trunc-engine::consume`.

## 11. Limits summary

| Item | Limit |
|---|---|
| Manifest region | 256 MiB |
| Dictionary | 1 MiB |
| Block decoded size | 1 GiB |
| Blocks | 2³² − 1 |
| Path | 4096 bytes, 256 components, 255 bytes per component |
