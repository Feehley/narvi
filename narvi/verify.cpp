// verify.cpp -- provenance checks (see verify.hpp).
#include "narvi/verify.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <fstream>
#include <map>
#include <unistd.h>

#include "narvi/model.hpp"
#include "narvi/rebuilders.hpp"
#include "narvi/repacker.hpp"

namespace narvi {

// --------------------------------------------------------------- byte-range diff
std::string ByteRange::str() const {
    char b[64];
    std::snprintf(b, sizeof(b), "0x%08llx..0x%08llx (%llu bytes)",
                  (unsigned long long)offset, (unsigned long long)end(),
                  (unsigned long long)length);
    return b;
}

std::vector<ByteRange> diff_ranges(const std::string& a, const std::string& b) {
    std::vector<ByteRange> ranges;
    size_t n = std::min(a.size(), b.size());
    long long start = -1;
    for (size_t i = 0; i < n; ++i) {
        if (a[i] != b[i]) {
            if (start < 0) start = (long long)i;
        } else if (start >= 0) {
            ranges.push_back({(uint64_t)start, (uint64_t)(i - (size_t)start)});
            start = -1;
        }
    }
    if (start >= 0)
        ranges.push_back({(uint64_t)start, (uint64_t)(n - (size_t)start)});
    if (a.size() != b.size()) {
        uint64_t longer = std::max(a.size(), b.size());
        uint64_t shorter = std::min(a.size(), b.size());
        if (!ranges.empty() && ranges.back().end() == shorter)
            ranges.back().length = longer - ranges.back().offset;
        else
            ranges.push_back({shorter, longer - shorter});
    }
    return ranges;
}

std::vector<std::string> name_ranges(const std::vector<ByteRange>& ranges, const Recipe& recipe) {
    std::vector<Segment> segs = recipe.segments;
    std::sort(segs.begin(), segs.end(),
              [](const Segment& x, const Segment& y) { return x.offset < y.offset; });
    std::vector<std::string> out;
    for (const auto& r : ranges) {
        std::string hits;
        for (const auto& s : segs) {
            if (s.offset < r.end() && s.end() > r.offset) {
                char tag[96];
                std::snprintf(tag, sizeof(tag), "%s@0x%llx",
                              s.is_region() ? s.type.c_str() : "gap",
                              (unsigned long long)s.offset);
                if (!hits.empty()) hits += ", ";
                hits += tag;
            }
        }
        out.push_back(r.str() + "  in " + (hits.empty() ? "(beyond original layout)" : hits));
    }
    return out;
}

// ------------------------------------------------------------- round-trip guard
static std::string slurp(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

std::string RoundTripResult::report(const Recipe* recipe) const {
    if (identical) {
        char b[96];
        std::snprintf(b, sizeof(b), "round-trip OK: no-edit repack is byte-identical (%llu bytes)",
                      (unsigned long long)output_size);
        return b;
    }
    if (!error.empty()) {
        return "ROUND-TRIP FAILED: a no-edit repack could not even complete:\n  " + error +
               "\nThe recipe cannot reproduce the source; do not trust edits until this is fixed.";
    }
    char head[192];
    std::snprintf(head, sizeof(head),
                  "ROUND-TRIP FAILED: no-edit repack differs from the original "
                  "(%llu -> %llu bytes, %zu range(s)).\n"
                  "The recipe cannot reproduce the source; do not trust edits until this is fixed.",
                  (unsigned long long)orig_size, (unsigned long long)output_size, ranges.size());
    std::string s = head;
    std::vector<std::string> lines =
        recipe ? name_ranges(ranges, *recipe) : std::vector<std::string>();
    if (!recipe) for (const auto& r : ranges) lines.push_back(r.str());
    size_t shown = std::min<size_t>(lines.size(), 20);
    for (size_t i = 0; i < shown; ++i) s += "\n  " + lines[i];
    if (lines.size() > 20)
        s += "\n  ... and " + std::to_string(lines.size() - 20) + " more";
    return s;
}

RoundTripResult roundtrip_check(const Recipe& recipe) {
    RoundTripResult res;
    std::string orig = slurp(recipe.source);
    res.orig_size = orig.size();

    char tmpl[] = "/tmp/narvi_rt_XXXXXX";
    int fd = mkstemp(tmpl);
    std::string out = tmpl;
    if (fd >= 0) close(fd);
    try {
        Repacker(recipe).repack(out, "fixed");
    } catch (const std::exception& e) {
        std::remove(out.c_str());
        res.identical = false;
        res.error = e.what();
        return res;
    }
    std::string got = slurp(out);
    std::remove(out.c_str());
    res.output_size = got.size();
    res.ranges = diff_ranges(orig, got);
    res.identical = (got == orig);
    return res;
}

// ------------------------------------------------------------- re-encode fidelity
std::string FidelityReport::line() const {
    std::string indent(2 * (size_t)depth, ' ');
    std::string mark, tail;
    if (status == "exact") { mark = "OK  "; tail = "reproduces original exactly"; }
    else if (status == "lossy") {
        mark = "WARN";
        tail = "re-encode differs (" + std::to_string(orig_length) + " -> " +
               std::to_string(reencoded_length) + "); editing rewrites the whole region";
    } else if (status == "no-encoder") {
        mark = "----";
        tail = "no rebuilder; editing this region (or nested edits under it) fails loudly";
    } else { mark = "ERR "; tail = detail.empty() ? "re-encode error" : detail; }
    char head[32];
    std::snprintf(head, sizeof(head), "[%s] 0x%08llx  ", mark.c_str(), (unsigned long long)offset);
    size_t pad = type.size() < 12 ? 12 - type.size() : 0;  // left-justify in a 12-wide field
    return indent + head + type + std::string(pad, ' ') + " " + tail;
}

static void fidelity_walk(const Segment& seg, const std::string& orig,
                          const RebuildContext& ctx, std::vector<FidelityReport>& out) {
    const Rebuilder& rb = rebuilder_for(seg.type);
    FidelityReport fr;
    fr.offset = seg.offset; fr.type = seg.type; fr.depth = seg.depth; fr.orig_length = orig.size();
    if (!rb.can_encode()) {
        fr.status = "no-encoder";
    } else {
        try {
            std::string re = rb.encode(seg, Working{}, ctx, orig);
            fr.reencoded_length = (long long)re.size();
            fr.status = (re == orig) ? "exact" : "lossy";
        } catch (const std::exception& e) {
            fr.status = "error";
            fr.detail = e.what();
        }
    }
    out.push_back(fr);

    std::map<std::string, std::vector<const Segment*>> by_file;
    for (const auto& c : seg.children) by_file[c.parent_file].push_back(&c);
    for (const auto& kv : by_file) {
        std::string base;
        try {
            base = rb.produced_file_bytes(seg, kv.first, ctx);
        } catch (const std::exception&) {
            continue;
        }
        for (const Segment* c : kv.second) {
            std::string corig = (c->offset <= base.size())
                ? base.substr(c->offset, std::min<uint64_t>(c->length, base.size() - c->offset))
                : std::string();
            fidelity_walk(*c, corig, ctx, out);
        }
    }
}

std::vector<FidelityReport> reencode_fidelity(const Recipe& recipe) {
    RebuildContext ctx;
    ctx.image = slurp(recipe.source);
    ctx.extract_root = recipe.extract_root;
    ctx.pad_byte = recipe.pad_byte;
    std::vector<FidelityReport> out;
    for (const auto& seg : recipe.regions()) {
        std::string orig = ctx.image.substr(seg.offset, seg.length);
        fidelity_walk(seg, orig, ctx, out);
    }
    return out;
}

// --------------------------------------------------------------------- combined
std::string VerifyResult::report(const Recipe* recipe, bool deep) const {
    std::string s = roundtrip.report(recipe);
    if (deep && !fidelity.empty()) {
        s += "\nre-encode fidelity (per region):";
        int n_lossy = 0, n_none = 0;
        for (const auto& f : fidelity) {
            s += "\n" + f.line();
            if (f.status == "lossy") ++n_lossy;
            if (f.status == "no-encoder") ++n_none;
        }
        if (n_lossy || n_none) {
            s += "\nnote: " + std::to_string(n_lossy) + " region(s) re-encode lossily, " +
                 std::to_string(n_none) + " have no encoder. Unchanged regions are still "
                 "spliced verbatim; this only matters for regions you edit.";
        }
    }
    return s;
}

VerifyResult verify_recipe(const Recipe& recipe, bool deep) {
    VerifyResult v;
    v.roundtrip = roundtrip_check(recipe);
    if (deep) v.fidelity = reencode_fidelity(recipe);
    return v;
}

}  // namespace narvi
