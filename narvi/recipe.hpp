// recipe.hpp -- ingest moria output into a repack recipe.
#pragma once
#include <optional>
#include <string>
#include <vector>

#include "narvi/model.hpp"

namespace narvi {

constexpr int RECIPE_VERSION = 2;

struct Recipe {
    std::string source;        // path to the original firmware image
    uint64_t filesize = 0;
    std::string extract_root;  // path to <file>.extracted
    std::vector<Segment> segments;
    uint8_t pad_byte = 0x00;

    // Build from moria's manifest.json (in extract_root) plus, optionally, the
    // `moria -j` identify JSON, plus the original image bytes.
    static Recipe from_extraction(const std::string& image_path,
                                  const std::string& extract_root = "",
                                  const std::string& identify_json = "");

    void save(const std::string& path) const;
    static Recipe load(const std::string& path);

    std::vector<Segment> regions() const;
};

}  // namespace narvi
