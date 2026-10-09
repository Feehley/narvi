// fdt.hpp -- a Flattened Device Tree reader: an in-place walker that locates a
// FIT's subimage payloads and the hash/signature nodes that cover them, plus a
// tree model and serializer for rebuilding a FIT after a length-changing edit.
#pragma once
#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace narvi {

constexpr uint32_t FDT_MAGIC = 0xD00DFEED;

struct FitHash {
    std::string algo;
    uint64_t payload_off = 0, payload_len = 0;
    uint64_t value_off = 0, value_len = 0;
};

struct FitSig {
    uint64_t payload_off = 0, payload_len = 0;
};

struct FitLayout {
    bool ok = false;
    std::array<uint64_t, 5> geom{};  // totalsize, off_struct, size_struct, off_strings, size_strings
    std::vector<FitHash> hashes;
    std::vector<FitSig> sigs;
};

// Walk the FDT at absolute offset `off` in `image`; collect FIT hash/signature
// coverage. Returns FitLayout{ok=false} if it is not a parseable FDT.
FitLayout parse_fit(const std::string& image, uint64_t off);


// --------------------------------------------------------------------------- //
// Tree model + serializer -- edit a FIT (or any DTB) and write it back.
// --------------------------------------------------------------------------- //
struct Prop {
    std::string name;
    std::string value;
    long long nameoff = -1;   // original strings-block offset, -1 if new
};

struct Node {
    std::string name;
    std::vector<Prop> props;
    std::vector<Node> children;

    Prop* prop(const std::string& n);
    const std::string* get(const std::string& n) const;   // value bytes or nullptr
    void set(const std::string& n, const std::string& v);
    Node* child(const std::string& n);
};

struct Fdt {
    Node root;
    std::string pre_struct;   // header..struct: memory-reservation map (+ pad)
    std::string strings;      // original strings block, appended to for new names
    uint32_t off_mem_rsvmap = 40, version = 17, last_comp_version = 16, boot_cpuid_phys = 0;

    Node* path(const std::string& p);
    std::string to_bytes() const;
};

// Parse an FDT into an editable tree; throws std::runtime_error if not an FDT.
Fdt parse_dtb(const std::string& image, uint64_t off = 0);

struct FitRebuildReport {
    std::vector<std::tuple<std::string, uint64_t, uint64_t>> resized;   // name, old, new
    std::vector<std::pair<std::string, std::string>> hashes;            // name, algo
    std::vector<std::string> invalidated_sigs;                          // name
    std::vector<std::string> external_skipped;                         // name
};

// Rebuild a FIT with new *stored* (already-compressed) subimage payloads. `edits`
// maps subimage name -> new embedded `data` bytes (any length). Updates data-size,
// recomputes hash nodes, flags signatures over changed data, re-serializes.
std::pair<std::string, FitRebuildReport>
rebuild_fit(const std::string& fit, const std::map<std::string, std::string>& edits,
            uint64_t off = 0);

}  // namespace narvi
