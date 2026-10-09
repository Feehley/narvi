// verify.hpp -- provenance checks.
//
// Extraction is lossy, so before trusting a recipe you want two guarantees:
//   1. Round-trip guard: a no-edit repack must reproduce the original byte for
//      byte. Unchanged regions/gaps are spliced verbatim, so a failure means
//      something structural is wrong (mis-derived span, region wrongly flagged
//      changed, bad fit). `plan` runs this by default.
//   2. Re-encode fidelity: for each editable region, re-encode from its unedited
//      content and compare to the original. "exact" means editing rewrites only
//      your change; "lossy" means the encoder does not reproduce the vendor's
//      stream so an edit re-encodes the whole region; "no-encoder" means edits
//      fail loudly.
// `narvi verify ORIG REPACKED` is a plain byte-range diff of two images.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "narvi/recipe.hpp"

namespace narvi {

struct ByteRange {
    uint64_t offset = 0;
    uint64_t length = 0;
    uint64_t end() const { return offset + length; }
    std::string str() const;
};

// Coalesced runs where a and b differ; a length mismatch becomes a trailing run.
std::vector<ByteRange> diff_ranges(const std::string& a, const std::string& b);

// Describe each range by the top-level segment(s) it overlaps.
std::vector<std::string> name_ranges(const std::vector<ByteRange>& ranges, const Recipe& recipe);

struct RoundTripResult {
    bool identical = false;
    std::vector<ByteRange> ranges;
    uint64_t output_size = 0;
    uint64_t orig_size = 0;
    std::string error;  // set if the no-edit repack could not complete
    std::string report(const Recipe* recipe = nullptr) const;
};

RoundTripResult roundtrip_check(const Recipe& recipe);

struct FidelityReport {
    uint64_t offset = 0;
    std::string type;
    int depth = 1;
    std::string status;            // "exact" | "lossy" | "no-encoder" | "error"
    uint64_t orig_length = 0;
    long long reencoded_length = -1;
    std::string detail;
    std::string line() const;
};

std::vector<FidelityReport> reencode_fidelity(const Recipe& recipe);

struct VerifyResult {
    RoundTripResult roundtrip;
    std::vector<FidelityReport> fidelity;
    std::string report(const Recipe* recipe, bool deep) const;
};

VerifyResult verify_recipe(const Recipe& recipe, bool deep);

}  // namespace narvi
