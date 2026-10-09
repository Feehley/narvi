// repacker.hpp -- turn a recipe (+ possibly-edited tree) back into an image.
#pragma once
#include <string>
#include <vector>

#include "narvi/model.hpp"
#include "narvi/rebuilders.hpp"
#include "narvi/recipe.hpp"
#include "narvi/fixups.hpp"

namespace narvi {

struct RegionReport {
    uint64_t offset;
    std::string type;
    bool changed;
    std::string action;   // "verbatim" | "rebuilt" | "rebuilt+padded" | "rebuilt+reflow"
    uint64_t orig_length;
    long long new_length; // -1 in status()
    int depth = 1;
};

struct RepackReport {
    std::vector<RegionReport> regions;
    uint64_t output_size = 0;
    bool identical = false;
    std::vector<FixupReport> fixups;
    std::string summary() const;
};

class Repacker {
public:
    explicit Repacker(Recipe recipe);

    std::vector<RegionReport> status() const;
    RepackReport repack(const std::string& out_path, const std::string& policy = "fixed",
                        bool do_fixups = true) const;

private:
    struct Rebuilt {
        std::string bytes;
        bool dirty;
        std::vector<RegionReport> reports;
    };
    Rebuilt rebuild(const Segment& seg, const std::string& orig) const;
    bool self_edited(const Segment& seg) const;
    bool dirty(const Segment& seg) const;
    std::pair<std::string, std::string> fit(const Segment& seg, const std::string& nw,
                                            const std::string& policy) const;

    Recipe recipe_;              // owned: a Repacker built from a temporary must
                                 // keep the recipe alive for its whole lifetime
    std::string image_;
    RebuildContext ctx_;
};

}  // namespace narvi
