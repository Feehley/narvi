# narvi (C++)

Repack firmware that [moria](https://github.com/nmatt0/moria) extracted — the
C++ sibling of moria and mithril, built against the same toolchain (C++20 +
zlib/lzma/zstd/lz4).

> Narvi was the Dwarf-smith who forged the Doors of Durin, the West-gate of
> Moria. moria opens the mountain and takes things out; narvi seals it back up.

## Why C++ fits

narvi needs exactly the libraries moria already links, so the port adds no new
runtime dependencies. The only things moria doesn't already have — a JSON
*parser* (moria only emits JSON) and SHA-256 — are vendored header-only
(`narvi/json.hpp`, `narvi/sha256.hpp`), keeping the zero-dependency stance.

## Build

```bash
make            # build the narvi binary + all test programs
make test       # build and run every suite
make install    # install the binary (PREFIX=/usr/local; use sudo, or DESTDIR=)
make clean      # reset the directory to its downloaded state

# or with CMake:
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
ctest --test-dir build            # roundtrip + nested + verify + fixups

# or straight g++ (note: output into build/, since ./narvi would collide
# with the narvi/ source directory):
mkdir -p build
g++ -std=c++20 -O2 -I. narvi/*.cpp -o build/narvi -lz -llzma -lzstd -llz4
# tests (link the library sources except cli.cpp, which owns main):
LIBS="narvi/codecs.cpp narvi/rebuilders.cpp narvi/recipe.cpp narvi/repacker.cpp narvi/verify.cpp narvi/fixups.cpp narvi/fdt.cpp"
g++ -std=c++20 -O2 -I. tests/roundtrip.cpp $LIBS -o build/roundtrip -lz -llzma -lzstd -llz4 && ./build/roundtrip
g++ -std=c++20 -O2 -I. tests/nested.cpp    $LIBS -o build/nested    -lz -llzma -lzstd -llz4 && ./build/nested
g++ -std=c++20 -O2 -I. tests/verify.cpp    $LIBS -o build/verify    -lz -llzma -lzstd -llz4 && ./build/verify
g++ -std=c++20 -O2 -I. tests/fixups.cpp    $LIBS -o build/fixups    -lz -llzma -lzstd -llz4 && ./build/fixups
g++ -std=c++20 -O2 -I. tests/fdt.cpp       $LIBS -o build/fdt       -lz -llzma -lzstd -llz4 && ./build/fdt
g++ -std=c++20 -O2 -I. tests/fitrebuild.cpp $LIBS -o build/fitrebuild -lz -llzma -lzstd -llz4 && ./build/fitrebuild
```

`make clean` removes `build/` and resets the directory to its downloaded
state.

Needs `zlib1g-dev liblzma-dev libzstd-dev liblz4-dev`. `mksquashfs`
(squashfs-tools) is only invoked if you edit a squashfs rootfs.

## Order of operations

**One command — `narvi init`** runs moria's extract + identify and plans in a
single step, so the baseline is captured the moment the firmware is unpacked:

```bash
narvi init firmware.bin -o fw.recipe.json        # extract + identify + plan
# ...edit files under firmware.bin.extracted/ ...
narvi status fw.recipe.json                       # confirm your edits show CHANGED
narvi repack fw.recipe.json -o firmware.repacked.bin --policy reflow
```

`init` needs `moria` on your PATH (or pass `--moria <path>`). It writes the
extraction (`firmware.bin.extracted/`), the identify JSON (`firmware.bin.identify.json`),
and the recipe.

Why one command matters: narvi decides "changed vs unchanged" by diffing your
files against a **baseline it captures at plan time**, so that baseline has to be
taken *before* you edit anything. `init` does extract and plan together, closing
the window where that can go wrong. The explicit form is the same three steps by
hand (`narvi plan` on the freshly-extracted tree):

```bash
moria -e   firmware.bin
moria -j   firmware.bin > firmware.identify.json
narvi plan firmware.bin --identify firmware.identify.json -o fw.recipe.json
# ...then edit, status, repack as above
```

> **Edit *after* planning, never before.** If you edit before `narvi plan` (or
> re-extract over your edits), the edited files *become* the baseline: narvi has
> nothing to compare against, so `status` reports `unchanged` and `repack` splices
> the original bytes back — silently dropping your edit (and the round-trip guard
> still says "byte-identical", because it reproduced the untouched original). If
> that happens, restore the file, re-plan (or re-`init`), then re-apply your edit.

Use `--policy reflow` whenever an edit changes a region's size (a rebuilt
squashfs or a grown FIT subimage never matches the vendor's exact byte size);
`fixed` keeps the image length constant and refuses an edit that would overflow
its slot.

## Use

```bash
narvi init   firmware.bin -o fw.recipe.json    # extract + identify + plan (needs moria on PATH)

# ...or the explicit steps:
moria -e firmware.bin
moria -j firmware.bin > firmware.identify.json

narvi plan   firmware.bin --identify firmware.identify.json -o fw.recipe.json
# plan runs a round-trip guard by default: a no-edit repack must reproduce the
# original byte-for-byte, else it prints ROUND-TRIP FAILED and exits non-zero.
# --deep additionally prints per-region re-encode fidelity; --no-verify skips it.

# ...edit files under firmware.bin.extracted/ ...
narvi status fw.recipe.json
narvi repack fw.recipe.json -o firmware.repacked.bin
# repack recomputes outer container checksums after splicing (see below);
# --no-fixups disables that pass.

# provenance:
narvi check  fw.recipe.json --deep                 # re-run guard + fidelity later
narvi verify firmware.bin firmware.repacked.bin --recipe fw.recipe.json
#   -> lists exactly which byte ranges moved, named by region

# inspect a FIT/DTB and confirm it re-serializes byte-for-byte:
narvi fdt firmware.itb
#   -> FDT @0x0 version=17 size=... round-trip=identical
```

Fidelity states: `exact` (editing rewrites only your change), `lossy` (the
encoder doesn't reproduce the vendor's stream, so an edit re-encodes the whole
region), `no-encoder` (edits fail loudly). Unchanged regions are always spliced
verbatim, so fidelity only matters for regions you actually edit.

### Container checksum fixups

Many images wrap their payload in a header carrying a checksum over the rest of
the file (a TRX CRC, a U-Boot env CRC, a Seama MD5, ...). moria usually descends
past these to the squashfs/kernel inside, so the wrapper header lands in a narvi
gap and is spliced back verbatim -- and an edit to something the checksum covers
would leave the image internally inconsistent. After assembling the image,
`repack` runs a fixup pass that repairs them, under one safety rule:

> **validate-on-original, recompute-on-output** -- a fixup fires only for a
> wrapper whose stored checksum was *correct in the source*, and only rewrites
> the field when the covered bytes actually changed.

So it never corrupts a false positive and a no-edit repack stays byte-identical.
Nested wrappers are patched inner-first. Recomputed today: **TRX** (CRC32),
**U-Boot env** (CRC32, anchored on moria's `uboot_env` finding), **Seama** (MD5),
and **FIT** (`.itb`) per-subimage **hash** nodes -- a small FDT walker
(`fdt.hpp`/`fdt.cpp`) finds each `/images/*/hash*` node and recomputes its
`crc32`/`sha1`/`sha256`/`md5` value in place over the subimage payload. A FIT
*signature* needs a private key, so a changed signed image is *flagged*
`signature-invalidated` (re-sign with `mkimage -F -k`) rather than shipped stale.
A length-changing subimage edit needs the FDT rebuilt rather than patched in
place -- see the reserializer below. `--no-fixups` disables the pass.

### FDT reserializer & general DTB editing

The in-place fixup handles size-neutral edits. When a subimage payload changes
*length*, the device-tree must be rebuilt -- property lengths, the struct and
strings blocks, header offsets and `totalsize` all move. `fdt.hpp`/`fdt.cpp`
carry a small tree model that does this and doubles as a general DTB editor:

```cpp
#include "narvi/fdt.hpp"
using namespace narvi;

// General DTB editing: parse -> edit -> serialize (byte-identical if unmodified).
Fdt fdt = parse_dtb(blob);                       // throws if not an FDT
fdt.path("/images/kernel")->set("compression", std::string("lzma\0", 5));
std::string out = fdt.to_bytes();

// FIT rebuild: replace a subimage payload of ANY length; hashes recomputed,
// signatures flagged. edits maps subimage name -> new *stored* bytes.
auto [new_fit, report] = rebuild_fit(blob, {{"kernel", new_kernel_bytes}});
// report.resized / report.hashes / report.invalidated_sigs / report.external_skipped
```

Fidelity rule: every existing property keeps its original name offset and the
memory-reservation block is preserved verbatim, so `parse_dtb(b).to_bytes() == b`
for a canonically-laid-out FDT. `rebuild_fit` updates `data-size`, recomputes each
`crc32`/`sha1`/`sha256`/`md5` hash node over the subimage's stored payload, and
flags signatures over changed data; external-data subimages are reported and left
untouched. `narvi fdt FILE` prints the tree summary and confirms the round-trip.

`repack` wires this in: a `fit` region whose subimage you edited is rebuilt
automatically -- re-compressing only the changed subimages (per the FDT's
`compression` property), reusing original stored bytes for the rest, then
reserializing. Grow past the slot with `--policy reflow`; otherwise the rebuilt
FIT is padded. A container nested in a subimage rebuilds inner-first. Automatic
re-compression covers `none`/`gzip`/`lzma` (deterministic, so a given edit
rebuilds identically every run); lz4/zstd are refused with a pointer to
`rebuild_fit` (future work).

Library API:

```cpp
#include "narvi/recipe.hpp"
#include "narvi/repacker.hpp"
using namespace narvi;

Recipe r = Recipe::from_extraction("firmware.bin", "firmware.bin.extracted",
                                   "firmware.identify.json");   // identify optional
r.save("fw.recipe.json");
// ...edit extracted files...
RepackReport rep = Repacker(r).repack("firmware.repacked.bin");   // policy "fixed" | "reflow"
std::printf("%s", rep.summary().c_str());
```

## Design

The original image is the source of truth. narvi tiles it into an ordered,
gap-free layout of **regions** (moria findings) and **gaps** (padding, vendor
headers, unidentified/encrypted bytes). On repack, unchanged regions and all
gaps are copied **byte for byte**; only edited regions are re-encoded, and their
parent headers/CRCs fixed up.

narvi reads only `offset`/`size`/`type`/`compression`/`endian`/`version`/`arch`/
`label` from moria's identify JSON and ignores every other field, so it tracks
moria's schema as it grows (newer additions like `category`, `mime`, `confidence`,
`entropy`, `references` are ignored). A moria finding type with no rebuilder
(e.g. a new filesystem) is spliced verbatim when unchanged and refuses a
size-changing edit rather than corrupting it.

| Region type | Behaviour |
|---|---|
| any type, unchanged | verbatim (byte-identical) |
| `gzip` `lzma` `xz` `zstd` `lz4` | re-compressed when edited (standalone `.lzma` re-encodes to alone format) |
| `uimage` (U-Boot legacy) | payload re-wrapped, `ih_size` + header/data CRC32 fixed |
| `squashfs` | rebuilt via external `mksquashfs`, reusing original compressor + block size |
| `cpio` (newc / crc initramfs) | rebuilt in-process: changed members re-emitted, `070702` data checksum recomputed, other members + trailer kept verbatim |
| other filesystems | verbatim if unchanged; clear error if edited (no rebuilder yet) |

Add a rebuilder by subclassing `Rebuilder` (`content_hash` + `rebuild`) and
extending `rebuilder_for()` in `narvi/rebuilders.cpp`.

**Layout policy** — `fixed` (default) pads a shortened region back to its slot
(`--pad 0xff` for NOR flash) and errors if a region overflows its partition;
`reflow` concatenates at natural sizes (only for images without fixed offsets).

## Limitations

Cryptographically sealed regions (vbmeta, FIT signatures, D-Link SHRS/DLK,
dm-verity) can't be resealed without vendor keys — narvi fixes plain CRCs, not
signatures. uImage payloads are handled in final on-image form (supply a
compressed payload already compressed, or model the inner region).

## Files

```
narvi/json.hpp        vendored JSON parser        narvi/recipe.{hpp,cpp}   ingest moria output
narvi/sha256.hpp      vendored SHA-256            narvi/repacker.{hpp,cpp} splice engine
narvi/model.hpp       layout model               narvi/cli.cpp            command line
narvi/codecs.{hpp,cpp}    compression + CRC      tests/roundtrip.cpp      end-to-end tests
narvi/rebuilders.{hpp,cpp} per-type re-encoding   tests/fitbuild.hpp       FIT builder (tests)
narvi/fdt.{hpp,cpp}   FDT walker + reserializer   narvi/sha1.hpp           vendored SHA-1
tests/fitrebuild.cpp  FIT rebuild-in-repack tests
```
