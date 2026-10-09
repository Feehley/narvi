#include "narvi/recipe.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>

#include "narvi/codecs.hpp"
#include "narvi/json.hpp"
#include "narvi/rebuilders.hpp"
#include "narvi/sha256.hpp"

namespace fs = std::filesystem;

namespace narvi {

static const std::string kExt = ".extracted/";

static std::string slurp(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) throw std::runtime_error("cannot read " + p);
    std::ostringstream ss; ss << f.rdbuf(); return ss.str();
}

static bool is_compressed(const std::string& t) {
    return t == "gzip" || t == "xz" || t == "zstd" || t == "lz4" || t == "lz4_legacy";
}

// Length of the region at `off` within buffer `buf`.
static uint64_t region_length(const std::string& buf, uint64_t off, const std::string& type,
                              const Json& entry, const Json* fnd) {
    if (auto* c = entry.find("consumed"); c && c->as_u64() > 0) return c->as_u64();
    if (fnd) { uint64_t sz = fnd->u64("size", 0); if (sz > 0) return sz; }
    if (is_compressed(type)) {
        long span = gzip_stream_span(buf, off);  // gzip only; others fall through
        if (span > 0) return (uint64_t)span;
    }
    if (type == "squashfs") {
        long long sz = squashfs_size(buf.substr(off));
        if (sz > 0) return (uint64_t)sz;
    }
    return buf.size() - off;  // last resort: run to end of buffer
}

static std::map<std::string, std::string> params_for(const Json* fnd) {
    std::map<std::string, std::string> p;
    if (!fnd) return p;
    for (const char* k : {"compression", "endian", "version", "arch", "label"}) {
        std::string v = fnd->s(k);
        if (!v.empty()) p[k] = v;
    }
    return p;
}

// The entry whose subdir is the longest proper prefix of `sub`.
static const Json* parent_of(const std::string& sub, const std::vector<const Json*>& all) {
    const Json* best = nullptr;
    size_t best_len = 0;
    for (auto* e : all) {
        std::string es = e->s("root");
        if (es != sub && sub.rfind(es + "/", 0) == 0 && es.size() > best_len) {
            best = e; best_len = es.size();
        }
    }
    return best;
}

static std::string parent_file_of(const std::string& parent_sub, const std::string& child_sub) {
    std::string tail = child_sub.substr(parent_sub.size() + 1);
    size_t idx = tail.find(kExt);
    return idx == std::string::npos ? tail : tail.substr(0, idx);
}

static Segment build_region(const Json& entry, uint64_t offset, uint64_t length,
                            const std::string& orig, const std::string& parent_file,
                            const std::map<std::string, std::vector<const Json*>>& kids,
                            const RebuildContext& ctx, const Json* fnd) {
    Segment s;
    s.offset = offset;
    s.length = length;
    s.kind = Kind::Region;
    s.type = entry.s("type");
    s.subdir = entry.s("root");
    s.depth = (int)entry.u64("depth", 1);
    s.status = entry.s("status");
    s.params = params_for(fnd);
    s.parent_file = parent_file;
    if (auto* w = entry.find("warnings"); w && w->is_arr())
        for (auto& x : w->arr) s.warnings.push_back(x.as_str());
    s.orig_sha256 = sha256_hex(orig);
    s.content_sha256 = rebuilder_for(s.type).self_hash(s, ctx);

    auto it = kids.find(s.subdir);
    if (it != kids.end()) {
        for (const Json* child : it->second) {
            std::string csub = child->s("root");
            std::string pf = parent_file_of(s.subdir, csub);
            std::string base = slurp((fs::path(ctx.extract_root) / s.subdir / pf).string());
            uint64_t coff = child->u64("offset", 0);
            uint64_t clen = region_length(base, coff, child->s("type"), *child, nullptr);
            s.children.push_back(build_region(*child, coff, clen,
                base.substr(coff, clen), pf, kids, ctx, nullptr));
        }
        std::sort(s.children.begin(), s.children.end(), [](const Segment& a, const Segment& b) {
            return a.parent_file != b.parent_file ? a.parent_file < b.parent_file
                                                  : a.offset < b.offset;
        });
    }
    return s;
}

static Segment make_gap(uint64_t off, uint64_t len, const std::string& image) {
    Segment g;
    g.offset = off; g.length = len; g.kind = Kind::Gap;
    g.orig_sha256 = sha256_hex(image.substr(off, len));
    return g;
}

Recipe Recipe::from_extraction(const std::string& image_path, const std::string& extract_root_in,
                               const std::string& identify_json) {
    std::string extract_root = extract_root_in.empty() ? image_path + ".extracted" : extract_root_in;
    std::string image = slurp(image_path);

    Json manifest = json_parse(slurp((fs::path(extract_root) / "manifest.json").string()));
    const Json* ex = manifest.find("extracted");
    std::vector<Json> entries_store;
    std::vector<const Json*> entries;
    if (ex && ex->is_arr())
        for (const auto& e : ex->arr)
            if (!e.s("root").empty()) entries.push_back(&e);

    std::map<uint64_t, const Json*> findings;
    Json idj;
    if (!identify_json.empty()) {
        idj = json_parse(slurp(identify_json));
        if (const Json* f = idj.find("findings"); f && f->is_arr())
            for (const auto& fnd : f->arr) findings[fnd.u64("offset", 0)] = &fnd;
    }

    Recipe r;
    r.source = fs::absolute(image_path).string();
    r.filesize = image.size();
    r.extract_root = fs::absolute(extract_root).string();

    RebuildContext ctx{image, r.extract_root, 0x00};

    // children-by-parent map, and the top-level entries.
    std::map<std::string, std::vector<const Json*>> kids;
    std::vector<const Json*> top;
    for (auto* e : entries) {
        const Json* p = parent_of(e->s("root"), entries);
        if (p) kids[p->s("root")].push_back(e);
        else top.push_back(e);
    }

    std::vector<Segment> regions;
    for (auto* e : top) {
        uint64_t off = e->u64("offset", 0);
        auto fit = findings.find(off);
        const Json* fnd = fit == findings.end() ? nullptr : fit->second;
        uint64_t len = region_length(image, off, e->s("type"), *e, fnd);
        regions.push_back(build_region(*e, off, len, image.substr(off, len), "", kids, ctx, fnd));
    }

    std::sort(regions.begin(), regions.end(),
              [](const Segment& a, const Segment& b) { return a.offset < b.offset; });

    // fill gaps
    uint64_t cursor = 0;
    for (auto& seg : regions) {
        if (seg.offset > cursor) r.segments.push_back(make_gap(cursor, seg.offset - cursor, image));
        r.segments.push_back(seg);
        cursor = std::max(cursor, seg.end());
    }
    if (cursor < image.size()) r.segments.push_back(make_gap(cursor, image.size() - cursor, image));

    validate_layout(r.segments, r.filesize);
    return r;
}

// --------------------------------------------------------------------------- //
// JSON persistence
// --------------------------------------------------------------------------- //
static void esc(std::ostream& o, const std::string& s) {
    o << '"';
    for (char c : s) {
        switch (c) {
            case '"': o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\n': o << "\\n"; break;
            case '\t': o << "\\t"; break;
            case '\r': o << "\\r"; break;
            default: o << c;
        }
    }
    o << '"';
}

static void emit_seg(std::ostream& o, const Segment& s, int ind) {
    std::string pad(ind, ' '), pad2(ind + 2, ' ');
    o << "{\n";
    o << pad2 << "\"offset\": " << s.offset << ",\n";
    o << pad2 << "\"length\": " << s.length << ",\n";
    o << pad2 << "\"kind\": \"" << kind_name(s.kind) << "\",\n";
    o << pad2 << "\"type\": "; esc(o, s.type); o << ",\n";
    o << pad2 << "\"subdir\": "; esc(o, s.subdir); o << ",\n";
    o << pad2 << "\"depth\": " << s.depth << ",\n";
    o << pad2 << "\"status\": "; esc(o, s.status); o << ",\n";
    o << pad2 << "\"params\": {";
    bool first = true;
    for (const auto& [k, v] : s.params) {
        if (!first) o << ", ";
        first = false;
        esc(o, k); o << ": "; esc(o, v);
    }
    o << "},\n";
    o << pad2 << "\"orig_sha256\": "; esc(o, s.orig_sha256); o << ",\n";
    o << pad2 << "\"content_sha256\": "; esc(o, s.content_sha256); o << ",\n";
    o << pad2 << "\"parent_file\": "; esc(o, s.parent_file); o << ",\n";
    o << pad2 << "\"children\": [";
    for (size_t i = 0; i < s.children.size(); ++i) {
        o << (i ? ",\n" : "\n") << std::string(ind + 4, ' ');
        emit_seg(o, s.children[i], ind + 4);
    }
    o << (s.children.empty() ? "" : "\n" + pad2) << "],\n";
    o << pad2 << "\"warnings\": [";
    for (size_t i = 0; i < s.warnings.size(); ++i) { if (i) o << ", "; esc(o, s.warnings[i]); }
    o << "]\n" << pad << "}";
}

void Recipe::save(const std::string& path) const {
    std::ofstream o(path);
    if (!o) throw std::runtime_error("cannot write " + path);
    o << "{\n  \"version\": " << RECIPE_VERSION << ",\n";
    o << "  \"source\": "; esc(o, source); o << ",\n";
    o << "  \"filesize\": " << filesize << ",\n";
    o << "  \"extract_root\": "; esc(o, extract_root); o << ",\n";
    o << "  \"pad_byte\": " << (int)pad_byte << ",\n";
    o << "  \"segments\": [";
    for (size_t i = 0; i < segments.size(); ++i) {
        o << (i ? ",\n" : "\n") << "    ";
        emit_seg(o, segments[i], 4);
    }
    o << (segments.empty() ? "" : "\n  ") << "]\n}\n";
}

static Segment parse_seg(const Json& j) {
    Segment s;
    s.offset = j.u64("offset", 0);
    s.length = j.u64("length", 0);
    s.kind = j.s("kind") == "region" ? Kind::Region : Kind::Gap;
    s.type = j.s("type");
    s.subdir = j.s("subdir");
    s.depth = (int)j.u64("depth", 1);
    s.status = j.s("status");
    if (auto* p = j.find("params"); p && p->is_obj())
        for (const auto& [k, v] : p->obj) s.params[k] = v.as_str();
    s.orig_sha256 = j.s("orig_sha256");
    s.content_sha256 = j.s("content_sha256");
    s.parent_file = j.s("parent_file");
    if (auto* ch = j.find("children"); ch && ch->is_arr())
        for (const auto& c : ch->arr) s.children.push_back(parse_seg(c));
    if (auto* w = j.find("warnings"); w && w->is_arr())
        for (const auto& x : w->arr) s.warnings.push_back(x.as_str());
    return s;
}

Recipe Recipe::load(const std::string& path) {
    Json j = json_parse(slurp(path));
    if (j.u64("version", 0) != RECIPE_VERSION)
        throw std::runtime_error("unsupported recipe version");
    Recipe r;
    r.source = j.s("source");
    r.filesize = j.u64("filesize", 0);
    r.extract_root = j.s("extract_root");
    r.pad_byte = (uint8_t)j.u64("pad_byte", 0);
    if (auto* segs = j.find("segments"); segs && segs->is_arr())
        for (const auto& sj : segs->arr) r.segments.push_back(parse_seg(sj));
    return r;
}

std::vector<Segment> Recipe::regions() const {
    std::vector<Segment> out;
    for (const auto& s : segments) if (s.is_region()) out.push_back(s);
    return out;
}

}  // namespace narvi
