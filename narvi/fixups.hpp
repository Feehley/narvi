// fixups.hpp -- container checksum fixups.
//
// Outer wrappers (TRX CRC, U-Boot env CRC, Seama MD5, ...) store a checksum over
// a span of the image that a splice may have changed. moria often does not model
// these wrappers as regions, so their header lands in a narvi gap and is spliced
// verbatim -- leaving the checksum stale after an edit. This pass runs after the
// image is assembled and repairs those checksums, under a rule that makes it safe
// to run blind: validate-on-original, recompute-on-output. A fixup fires only for
// a wrapper whose stored checksum was correct in the original image, and only
// rewrites the field when the covered bytes actually changed (so a no-edit repack
// stays byte-identical). Checksums needing a private key (signed FIT) are flagged,
// never fabricated.
#pragma once
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "narvi/model.hpp"

namespace narvi {

struct FixupReport {
    std::string kind;      // "trx" | "uboot_env" | "seama" | "fit"
    uint64_t offset = 0;
    std::string status;    // "fixed" | "unchanged" | "signature-invalidated" | "skipped"
    std::string detail;
    std::string line() const;
};

std::pair<std::string, std::vector<FixupReport>>
apply_fixups(const std::string& original, const std::string& output,
             const std::vector<Segment>& segments);

}  // namespace narvi
