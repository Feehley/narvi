// model.hpp -- the layout model.
//
// An image is tiled by an ordered list of Segments covering [0, filesize) with
// no gaps and no overlaps. Every byte belongs to exactly one segment, which is
// what makes byte-identical repacking of untouched regions possible.
#pragma once
#include <algorithm>
#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace narvi {

enum class Kind { Region, Gap };

struct Segment {
    uint64_t offset = 0;         // absolute offset in the source image
    uint64_t length = 0;         // exact byte span in the source image
    Kind kind = Kind::Gap;
    std::string type;            // moria type for regions ("squashfs", "gzip", ...)
    std::string subdir;          // extracted subdir, relative to the extraction root
    int depth = 1;
    std::string status;
    std::map<std::string, std::string> params;  // comp, block_size, endian, ...
    std::string orig_sha256;     // sha256 of the ORIGINAL bytes of this span
    std::string content_sha256;  // sha256 of this region's own editable content, at plan time
    std::string parent_file;     // produced file (rel to parent subdir) a nested region lives in
    std::vector<Segment> children;  // nested regions (containers found inside this one)
    std::vector<std::string> warnings;

    uint64_t end() const { return offset + length; }
    bool is_region() const { return kind == Kind::Region; }
};

inline const char* kind_name(Kind k) { return k == Kind::Region ? "region" : "gap"; }

// Throw unless the segments tile [0, filesize) exactly.
inline void validate_layout(std::vector<Segment>& segs, uint64_t filesize) {
    std::sort(segs.begin(), segs.end(),
              [](const Segment& a, const Segment& b) { return a.offset < b.offset; });
    uint64_t cursor = 0;
    char buf[128];
    for (const auto& s : segs) {
        if (s.offset != cursor) {
            std::snprintf(buf, sizeof(buf),
                "layout hole/overlap: expected next segment at 0x%llx, got 0x%llx",
                (unsigned long long)cursor, (unsigned long long)s.offset);
            throw std::runtime_error(buf);
        }
        cursor = s.end();
    }
    if (cursor != filesize) {
        std::snprintf(buf, sizeof(buf),
            "layout does not cover the file: ends at 0x%llx, file is 0x%llx bytes",
            (unsigned long long)cursor, (unsigned long long)filesize);
        throw std::runtime_error(buf);
    }
}

}  // namespace narvi
