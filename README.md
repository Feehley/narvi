# narvi

**IoT firmware repacking**

narvi puts firmware back together after you've taken it apart. Point it at an image that [moria](https://github.com/nmatt0/moria) extracted, edit a file in the tree, and narvi re-encodes only what you touched and splices the rest back byte-for-byte. Named for the Dwarf who forged the Doors of Durin, the West-gate of Moria — moria opens the mountain and takes things out, narvi seals it back up.

## Why narvi

- **Only re-encodes what changed.** Unchanged regions and gaps are copied verbatim, so a no-edit repack is byte-identical to the original. Edit one file and that region is the only thing rebuilt.
- **Rebuilds the common formats in-process.** gzip / lzma / xz / zstd / lz4 streams, U-Boot uImage (CRCs fixed), SquashFS (via `mksquashfs`), and U-Boot FIT images (device-tree reserialized, hashes recomputed).
- **Recursive, the same way moria is.** A gzip-wrapped FIT with a nested kernel rebuilds from the inside out — innermost payload first, then every container that wraps it.
- **Fixes the checksums vendors hide in headers.** TRX CRC32, Seama MD5, U-Boot environment CRC, and FIT hash nodes are recomputed after splicing, under a validate-on-original rule so a correct checksum is never clobbered.
- **Won't ship a silent mistake.** A region it can't rebuild fails loudly instead of writing stale bytes, and a signed FIT whose data changed is flagged, not quietly invalidated.
- **No runtime dependencies beyond the codecs.** JSON parser, SHA-256/1, and MD5 are vendored; narvi links the same zlib / lzma / zstd / lz4 that moria already needs.

## Build & Install

```
[~]> make
[~]> make test
[~]> sudo make install          # PREFIX=/usr/local; or make install PREFIX=~/.local
```

Build needs a C++20 compiler and the zlib, liblzma, lz4, and zstd development libraries. On Debian/Ubuntu: `sudo apt install g++ zlib1g-dev liblzma-dev liblz4-dev libzstd-dev`. CMake works too (`cmake -S . -B build && cmake --build build -j`). `make clean` resets the tree to its downloaded state. SquashFS repacking shells out to `mksquashfs` (`squashfs-tools`) — everything else is in-process.

## Usage

```
narvi init   FIRMWARE [-o recipe.json] [--moria PATH] [--force] [--no-verify]
narvi plan   IMAGE [--extracted DIR] [--identify JSON] [-o recipe.json] [--deep]
narvi status RECIPE
narvi repack RECIPE [-o out.bin] [--policy fixed|reflow] [--pad 0xNN] [--no-fixups]
narvi verify ORIG REPACKED [--recipe recipe.json]
narvi check  RECIPE [--deep]
narvi fdt    FILE [--offset 0xN]
```

`init` is the one you want. It runs moria's extract and identify and then plans, all in one step:

```
[~]> narvi init firmware.bin -o rec.json
[1/3] extracting   moria -e firmware.bin
[2/3] identifying  moria -j firmware.bin > firmware.bin.identify.json
[3/3] planning

planned 2 region(s), 1 gap(s) over 4456452 bytes
recipe: rec.json
round-trip OK: no-edit repack is byte-identical (4456452 bytes)

Next: edit files under firmware.bin.extracted/, then
  narvi repack rec.json -o <output.bin> --policy reflow
```

Edit a file under `firmware.bin.extracted/`, check what moved, and write the new image:

```
[~]> narvi status rec.json
  0x00000000  fit          unchanged
  0x000401c0  squashfs     CHANGED

[~]> narvi repack rec.json -o patched.bin --policy reflow
output: 4458456 bytes
  0x00000000  fit          unchanged  verbatim         262144 -> 262144
  0x000401c0  squashfs     changed    rebuilt+reflow   4194308 -> 4196312
  checksum fixups:
    0x00000000  trx        fixed  (crc32 recomputed)
wrote patched.bin
```

## Order of operations

**Plan before you edit.** This is the one rule that will bite you if you skip it.

narvi decides changed-versus-unchanged by diffing your files against a baseline it captures at plan time. So the baseline has to be taken while the tree is still pristine:

1. `narvi init firmware.bin -o rec.json`  — extract + identify + plan (baseline captured here)
2. edit files under `firmware.bin.extracted/`
3. `narvi status rec.json`  — confirm the regions you touched say `CHANGED`
4. `narvi repack rec.json -o patched.bin --policy reflow`

If you edit *before* planning, the edited files become the baseline. narvi has nothing to compare against, so `status` says `unchanged`, `repack` splices the original bytes back, and the round-trip guard still reports "byte-identical" because it faithfully reproduced the untouched original. If that happens, restore the file, re-run `init`, then edit.

## What narvi rebuilds

`-e` left you a directory per region. Change a file in one and narvi re-encodes that region on repack:

- **Compressed streams:** gzip, lzma (legacy standalone `.lzma`, alone format), xz, zstd, lz4 — re-compressed from the decoded payload moria wrote to disk.
- **U-Boot uImage:** payload re-wrapped, `ih_size` and both header and data CRC32s fixed.
- **SquashFS:** rebuilt with `mksquashfs`, reusing the original compressor and block size from the superblock.
- **U-Boot FIT (`.itb`):** the device-tree is reserialized so a subimage can grow or shrink, each subimage re-compressed per its `compression` property (none / gzip / lzma), every `crc32` / `sha1` / `sha256` / `md5` hash node recomputed over the new payload, and a signature over changed data flagged to re-sign.
- **Anything else:** spliced verbatim when unchanged; a clear error if you edited it and no rebuilder exists yet.

Growing a region past its original size shifts everything after it, so pass `--policy reflow`. The default `fixed` keeps the image length constant and pads a region that got smaller — or refuses one that got bigger.

## Device trees

narvi carries a small FDT tree model, so it doubles as a device-tree editor outside the repack flow. `narvi fdt FILE` prints a FIT/DTB summary and confirms the blob re-serializes byte-for-byte:

```
[~]> narvi fdt firmware.itb
FDT @0x0  version=17  size=383  round-trip=identical
images: 1
  kernel           data=59 comp=gzip hash=sha256,crc32
```

## Scope

narvi repacks what moria identifies and extracts. It does not identify or carve on its own — that's moria's job — and it does not scan for secrets, CVEs, or licenses (see [mithril](https://github.com/nmatt0/mithril)).

## Shoutouts!

- [moria](https://github.com/nmatt0/moria) — the extractor narvi is built to pair with; narvi reads its identify JSON and extraction layout directly.
- The zlib, liblzma, zstd, and lz4 projects — the codecs that do the real compression work.

## Follow on steps

- Rebuilders for more filesystems (JFFS2, UBIFS, ext4) so you can edit inside them, not just splice them verbatim.
- lz4 / zstd FIT subimages (the codecs are linked; the FIT path just doesn't wire them yet).
- External-data FITs (`mkimage -E`), where payloads sit after the device-tree — currently reported and left alone.

## License

MIT, see `LICENSE`.
