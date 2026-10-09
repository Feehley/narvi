// rebuilders.hpp -- per-type change detection + re-encoding, recursion-aware.
//
// A region is re-encoded ONLY when its own content changed OR a nested child
// changed; unchanged regions are spliced verbatim by the Repacker. A container's
// encode() receives `working`: a map from produced file (e.g. "decompressed",
// "payload", a path in a tree) to already-rebuilt bytes, and encodes using those.
#pragma once
#include <map>
#include <string>

#include "narvi/model.hpp"

namespace narvi {

std::string read_file(const std::string& path);
bool file_exists(const std::string& path);
std::string path_join(const std::string& a, const std::string& b);
std::string sha256_file(const std::string& path);
std::string hash_tree(const std::string& root);  // excludes nested *.extracted subtrees

// squashfs superblock parsing.
long squashfs_block(const std::string& region);
std::string squashfs_comp(const std::string& region);
long long squashfs_size(const std::string& region);  // bytes_used, -1 if unknown

struct RebuildContext {
    std::string image;
    std::string extract_root;
    uint8_t pad_byte = 0x00;
    std::string subdir_path(const Segment& s) const { return path_join(extract_root, s.subdir); }
};

using Working = std::map<std::string, std::string>;  // produced-file relpath -> bytes

class Rebuilder {
public:
    virtual ~Rebuilder() = default;
    virtual bool can_encode() const { return true; }
    virtual std::string self_hash(const Segment& s, const RebuildContext& c) const {
        return hash_tree(c.subdir_path(s));
    }
    virtual std::string produced_file_bytes(const Segment& s, const std::string& rel,
                                            const RebuildContext& c) const {
        return read_file(path_join(c.subdir_path(s), rel));
    }
    // `orig` = the region's original bytes (image slice at top level, or the
    // slice of the parent's produced file for a nested region).
    virtual std::string encode(const Segment& s, const Working& working,
                               const RebuildContext& c, const std::string& orig) const = 0;
};

const Rebuilder& rebuilder_for(const std::string& type);

constexpr uint32_t UIMAGE_MAGIC = 0x27051956;
constexpr size_t UIMAGE_HDR = 64;

}  // namespace narvi
