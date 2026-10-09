#include "narvi/repacker.hpp"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <functional>
#include <map>
#include <sstream>
#include <stdexcept>

#include "narvi/sha256.hpp"

namespace narvi {

static std::string slurp(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) throw std::runtime_error("cannot read " + p);
    std::ostringstream ss; ss << f.rdbuf(); return ss.str();
}

Repacker::Repacker(Recipe recipe)
    : recipe_(std::move(recipe)), image_(slurp(recipe_.source)),
      ctx_{image_, recipe_.extract_root, recipe_.pad_byte} {
    if (image_.size() != recipe_.filesize)
        throw std::runtime_error("source image size changed since planning; rebuild the recipe");
}

bool Repacker::self_edited(const Segment& seg) const {
    return rebuilder_for(seg.type).self_hash(seg, ctx_) != seg.content_sha256;
}

bool Repacker::dirty(const Segment& seg) const {
    if (self_edited(seg)) return true;
    for (const auto& c : seg.children) if (dirty(c)) return true;
    return false;
}

std::vector<RegionReport> Repacker::status() const {
    std::vector<RegionReport> out;
    std::function<void(const Segment&)> walk = [&](const Segment& s) {
        out.push_back({s.offset, s.type, dirty(s), "", s.length, -1, s.depth});
        for (const auto& c : s.children) walk(c);
    };
    for (const auto& s : recipe_.segments) if (s.is_region()) walk(s);
    return out;
}

Repacker::Rebuilt Repacker::rebuild(const Segment& seg, const std::string& orig) const {
    const Rebuilder& rb = rebuilder_for(seg.type);
    bool is_dirty = self_edited(seg);
    Working working;
    std::vector<RegionReport> reports;

    // Group children by the produced file they live in.
    std::map<std::string, std::vector<const Segment*>> by_file;
    for (const auto& c : seg.children) by_file[c.parent_file].push_back(&c);

    for (auto& [pf, children] : by_file) {
        std::string base = rb.produced_file_bytes(seg, pf, ctx_);
        struct Built { const Segment* c; std::string bytes; bool dirty; };
        std::vector<Built> built;
        for (const Segment* c : children) {
            std::string corig = base.substr(c->offset, c->length);
            Rebuilt r = rebuild(*c, corig);
            built.push_back({c, std::move(r.bytes), r.dirty});
            reports.insert(reports.end(), r.reports.begin(), r.reports.end());
        }
        // Splice high offset -> low so earlier splices do not shift later ones.
        std::sort(built.begin(), built.end(),
                  [](const Built& a, const Built& b) { return a.c->offset > b.c->offset; });
        bool changed = false;
        std::string newbase = base;
        for (auto& b : built) {
            if (b.dirty) {
                changed = true;
                newbase = newbase.substr(0, b.c->offset) + b.bytes +
                          newbase.substr(b.c->offset + b.c->length);
            }
            reports.push_back({b.c->offset, b.c->type, b.dirty,
                               b.dirty ? "rebuilt" : "verbatim", b.c->length,
                               b.dirty ? (long long)b.bytes.size() : (long long)b.c->length,
                               b.c->depth});
        }
        if (changed) { is_dirty = true; working[pf] = newbase; }
    }

    if (!is_dirty) {
        if (!seg.orig_sha256.empty() && sha256_hex(orig) != seg.orig_sha256) {
            char buf[200];
            std::snprintf(buf, sizeof(buf),
                "original bytes for %s @0x%llx do not match the recipe hash; the source "
                "image is not the one this recipe was built from",
                seg.type.c_str(), (unsigned long long)seg.offset);
            throw std::runtime_error(buf);
        }
        return {orig, false, reports};
    }
    return {rb.encode(seg, working, ctx_, orig), true, reports};
}

std::pair<std::string, std::string> Repacker::fit(const Segment& seg, const std::string& nw,
                                                  const std::string& policy) const {
    if (policy == "reflow") return {"rebuilt+reflow", nw};
    if (nw.size() > seg.length) {
        char buf[220];
        std::snprintf(buf, sizeof(buf),
            "region %s @0x%llx re-encoded to %zu bytes, larger than its %llu-byte slot. "
            "Reduce content, or use policy=reflow if downstream offsets may shift.",
            seg.type.c_str(), (unsigned long long)seg.offset, nw.size(),
            (unsigned long long)seg.length);
        throw std::runtime_error(buf);
    }
    if (nw.size() < seg.length)
        return {"rebuilt+padded", nw + std::string(seg.length - nw.size(), (char)ctx_.pad_byte)};
    return {"rebuilt", nw};
}

RepackReport Repacker::repack(const std::string& out_path, const std::string& policy,
                              bool do_fixups) const {
    if (policy != "fixed" && policy != "reflow")
        throw std::runtime_error("policy must be 'fixed' or 'reflow'");
    std::string blob;
    std::vector<RegionReport> reports;

    std::vector<Segment> ordered = recipe_.segments;
    std::sort(ordered.begin(), ordered.end(),
              [](const Segment& a, const Segment& b) { return a.offset < b.offset; });

    for (const auto& seg : ordered) {
        if (seg.kind == Kind::Gap) {
            blob += image_.substr(seg.offset, seg.length);
            continue;
        }
        std::string orig = image_.substr(seg.offset, seg.length);
        Rebuilt r = rebuild(seg, orig);
        if (!r.dirty) {
            blob += r.bytes;
            reports.push_back({seg.offset, seg.type, false, "verbatim", seg.length,
                               (long long)seg.length, 1});
        } else {
            auto [action, fitted] = fit(seg, r.bytes, policy);
            blob += fitted;
            reports.push_back({seg.offset, seg.type, true, action, seg.length,
                               (long long)fitted.size(), 1});
        }
        reports.insert(reports.end(), r.reports.begin(), r.reports.end());
    }

    std::vector<FixupReport> fixups;
    if (do_fixups) {
        auto [patched, freps] = apply_fixups(image_, blob, recipe_.segments);
        blob = std::move(patched);
        fixups = std::move(freps);
    }

    std::ofstream o(out_path, std::ios::binary);
    if (!o) throw std::runtime_error("cannot write " + out_path);
    o.write(blob.data(), (std::streamsize)blob.size());

    RepackReport rep;
    rep.regions = std::move(reports);
    rep.output_size = blob.size();
    rep.identical = (blob == image_);
    rep.fixups = std::move(fixups);
    return rep;
}

std::string RepackReport::summary() const {
    std::ostringstream o;
    o << "output: " << output_size << " bytes"
      << (identical ? "  (byte-identical to source)" : "") << "\n";
    char line[256];
    for (const auto& r : regions) {
        std::string indent(2 * r.depth, ' ');
        std::snprintf(line, sizeof(line), "%s0x%08llx  %-12s %-9s %-16s %llu -> %lld",
            indent.c_str(), (unsigned long long)r.offset, r.type.c_str(),
            r.changed ? "changed" : "unchanged", r.action.c_str(),
            (unsigned long long)r.orig_length, r.new_length);
        o << line << "\n";
    }
    bool any = false;
    for (const auto& f : fixups) if (f.status != "unchanged") any = true;
    if (any) {
        o << "checksum fixups:\n";
        for (const auto& f : fixups)
            if (f.status != "unchanged") o << f.line() << "\n";
    }
    return o.str();
}

}  // namespace narvi
