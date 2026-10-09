// fixups.cpp -- container checksum fixups incl. FIT hash recompute (see fixups.hpp
// for the full rationale).
#include "narvi/fixups.hpp"

#include <algorithm>
#include <cstdio>
#include <map>
#include <set>

#include "narvi/codecs.hpp"   // crc32_of
#include "narvi/fdt.hpp"      // parse_fit
#include "narvi/md5.hpp"      // md5_bytes
#include "narvi/sha1.hpp"     // sha1_bytes
#include "narvi/sha256.hpp"   // sha256_hex

namespace narvi {

std::string FixupReport::line() const {
    char head[64];
    std::snprintf(head, sizeof(head), "  0x%08llx  ", (unsigned long long)offset);
    size_t pad = kind.size() < 10 ? 10 - kind.size() : 0;
    std::string s = head + kind + std::string(pad, ' ') + " " + status;
    if (!detail.empty()) s += "  (" + detail + ")";
    return s;
}

namespace {

std::string sha256_bytes(const std::string& data) {
    std::string hex = sha256_hex(data), raw(hex.size() / 2, '\0');
    auto nyb = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return 0;
    };
    for (size_t i = 0; i < raw.size(); i++)
        raw[i] = (char)((nyb(hex[2*i]) << 4) | nyb(hex[2*i+1]));
    return raw;
}

std::string digest(const std::string& algo, const std::string& data, const std::string& endian) {
    if (algo == "crc32") {
        uint32_t v = crc32_of(data);
        std::string s(4, '\0');
        if (endian == "le") for (int i = 0; i < 4; i++) s[i] = (char)(uint8_t)(v >> (8 * i));
        else                for (int i = 0; i < 4; i++) s[i] = (char)(uint8_t)(v >> (8 * (3 - i)));
        return s;
    }
    if (algo == "md5") return md5_bytes(data);
    if (algo == "sha1") return sha1_bytes(data);
    if (algo == "sha256") return sha256_bytes(data);
    return std::string();
}

int digest_len(const std::string& algo) {
    if (algo == "crc32") return 4;
    if (algo == "md5") return 16;
    if (algo == "sha1") return 20;
    if (algo == "sha256") return 32;
    return -1;
}

uint32_t u32le(const std::string& b, size_t o) {
    return (uint32_t)(uint8_t)b[o] | ((uint32_t)(uint8_t)b[o+1] << 8) |
           ((uint32_t)(uint8_t)b[o+2] << 16) | ((uint32_t)(uint8_t)b[o+3] << 24);
}
uint32_t u32be(const std::string& b, size_t o) {
    return ((uint32_t)(uint8_t)b[o] << 24) | ((uint32_t)(uint8_t)b[o+1] << 16) |
           ((uint32_t)(uint8_t)b[o+2] << 8) | (uint32_t)(uint8_t)b[o+3];
}
uint16_t u16be(const std::string& b, size_t o) {
    return (uint16_t)(((uint32_t)(uint8_t)b[o] << 8) | (uint32_t)(uint8_t)b[o+1]);
}
std::vector<size_t> find_all(const std::string& hay, const std::string& needle) {
    std::vector<size_t> out;
    size_t i = hay.find(needle);
    while (i != std::string::npos) { out.push_back(i); i = hay.find(needle, i + 1); }
    return out;
}

struct Action {
    std::string kind;
    uint64_t header_off = 0;
    uint64_t covered_off = 0, covered_len = 0;
    std::string algo;
    std::string endian = "le";
    uint64_t value_off = 0, value_len = 0;
    bool recomputable = true;
};

void trx_actions(const std::string& orig, std::vector<Action>& out) {
    for (size_t o : find_all(orig, "HDR0")) {
        if (o + 16 > orig.size()) continue;
        uint32_t total = u32le(orig, o + 4), stored = u32le(orig, o + 8);
        if (total < 16 || o + total > orig.size()) continue;
        if (crc32_of(orig.substr(o + 12, total - 12)) == stored)
            out.push_back({"trx", o, o + 12, total - 12u, "crc32", "le", o + 8, 4, true});
    }
}
void seama_actions(const std::string& orig, std::vector<Action>& out) {
    const std::string magic("\x5e\xa3\xa4\x17", 4);
    for (size_t o : find_all(orig, magic)) {
        if (o + 28 > orig.size()) continue;
        uint32_t metasize = u16be(orig, o + 6), size = u32be(orig, o + 8);
        uint64_t body_off = o + 28, body_len = (uint64_t)metasize + size;
        if (body_off + body_len > orig.size()) continue;
        if (md5_bytes(orig.substr(body_off, body_len)) == orig.substr(o + 12, 16))
            out.push_back({"seama", o, body_off, body_len, "md5", "le", o + 12, 16, true});
    }
}
void uboot_env_actions(const std::string& orig, const std::vector<Segment>& segs,
                       std::vector<Action>& out) {
    static const uint64_t sizes[] = {0x1000, 0x2000, 0x4000, 0x8000, 0x10000,
                                     0x20000, 0x40000, 0x80000, 0x100000, 0x200000};
    for (const auto& s : segs) {
        if (s.type != "uboot_env" || s.offset + 8 > orig.size()) continue;
        uint64_t o = s.offset;
        uint32_t stored = u32le(orig, o);
        bool found = false; uint64_t hl_f = 4, total_f = 0;
        for (uint64_t hl : {(uint64_t)4, (uint64_t)5}) {
            std::vector<uint64_t> cands = {s.length};
            for (uint64_t t : sizes) if (o + t <= orig.size()) cands.push_back(t);
            for (uint64_t total : cands) {
                if (total <= hl || o + total > orig.size()) continue;
                if (crc32_of(orig.substr(o + hl, total - hl)) == stored) {
                    found = true; hl_f = hl; total_f = total; break;
                }
            }
            if (found) break;
        }
        if (found)
            out.push_back({"uboot_env", o, o + hl_f, total_f - hl_f, "crc32", "le", o, 4, true});
    }
}

// FIT: walk the FDT, recompute each /images/*/hash* value over its subimage
// payload. Eligible only if valid-in-original AND structurally present in output.
void fit_actions(const std::string& orig, const std::string& output,
                 std::vector<Action>& out, std::vector<FixupReport>& reports) {
    const std::string magic("\xd0\x0d\xfe\xed", 4);
    for (size_t o : find_all(orig, magic)) {
        FitLayout oi = parse_fit(orig, o);
        if (!oi.ok || (oi.hashes.empty() && oi.sigs.empty())) continue;
        FitLayout oo = parse_fit(output, o);
        if (!oo.ok) continue;
        if (oo.geom != oi.geom) {
            // FIT changed size -> it was rebuilt (by the FIT rebuilder). If it is
            // internally consistent, that rebuild fixed the hashes; stay quiet
            // (flag only a now-stale signature). Otherwise flag it.
            bool consistent = !oo.hashes.empty();
            for (const auto& h : oo.hashes) {
                if (digest(h.algo, output.substr(h.payload_off, h.payload_len), "be") !=
                    output.substr(h.value_off, h.value_len)) { consistent = false; break; }
            }
            if (consistent) {
                if (!oo.sigs.empty())
                    reports.push_back({"fit", o, "signature-invalidated",
                                       "signature over rebuilt data; re-sign (e.g. mkimage -F -k)"});
            } else {
                reports.push_back({"fit", o, "signature-invalidated",
                                   "FDT changed but hashes inconsistent; rebuild needed"});
            }
            continue;
        }
        std::set<std::string> out_hashes;
        auto hkey = [](const FitHash& h) {
            return h.algo + ":" + std::to_string(h.payload_off) + ":" + std::to_string(h.payload_len)
                 + ":" + std::to_string(h.value_off) + ":" + std::to_string(h.value_len);
        };
        for (const auto& h : oo.hashes) out_hashes.insert(hkey(h));
        std::set<std::string> out_sigs;
        for (const auto& s : oo.sigs) out_sigs.insert(std::to_string(s.payload_off) + ":" + std::to_string(s.payload_len));

        for (const auto& h : oi.hashes) {
            if (!out_hashes.count(hkey(h))) continue;
            int want = digest_len(h.algo);
            if (want < 0 || (uint64_t)want != h.value_len) continue;
            if (digest(h.algo, orig.substr(h.payload_off, h.payload_len), "be") !=
                orig.substr(h.value_off, h.value_len)) continue;   // validate-on-original
            out.push_back({"fit", o, h.payload_off, h.payload_len, h.algo, "be",
                           h.value_off, h.value_len, true});
        }
        for (const auto& s : oi.sigs) {
            if (out_sigs.count(std::to_string(s.payload_off) + ":" + std::to_string(s.payload_len)))
                out.push_back({"fit", o, s.payload_off, s.payload_len, "none", "be", 0, 0, false});
        }
    }
}

}  // namespace

std::pair<std::string, std::vector<FixupReport>>
apply_fixups(const std::string& original, const std::string& output,
             const std::vector<Segment>& segments) {
    std::vector<Action> wrapper;
    trx_actions(original, wrapper);
    seama_actions(original, wrapper);
    uboot_env_actions(original, segments, wrapper);
    bool has_fdt = original.find(std::string("\xd0\x0d\xfe\xed", 4)) != std::string::npos;

    std::vector<FixupReport> reports;
    if (wrapper.empty() && !has_fdt) return {output, reports};

    if (output.size() != original.size()) {
        for (const auto& a : wrapper)
            reports.push_back({a.kind, a.header_off, "skipped", "layout reflowed; fixed layout required"});
        return {output, reports};
    }

    std::vector<Action> fit;
    fit_actions(original, output, fit, reports);
    std::vector<Action> actions = wrapper;
    actions.insert(actions.end(), fit.begin(), fit.end());
    std::sort(actions.begin(), actions.end(),
              [](const Action& a, const Action& b) { return a.covered_len < b.covered_len; });

    std::string buf = output;
    std::map<uint64_t, std::pair<std::set<std::string>, bool>> fit_stats;

    for (const auto& a : actions) {
        std::string cov = buf.substr(a.covered_off, a.covered_len);
        bool changed = cov != original.substr(a.covered_off, a.covered_len);
        if (!a.recomputable) {                       // FIT signature
            auto& st = fit_stats[a.header_off];
            if (changed) st.second = true;
            continue;
        }
        std::string nw = digest(a.algo, cov, a.endian);
        std::string cur = buf.substr(a.value_off, a.value_len);
        bool acted = nw != cur;
        if (acted) for (size_t i = 0; i < nw.size(); i++) buf[a.value_off + i] = nw[i];
        if (a.kind == "fit") {
            auto& st = fit_stats[a.header_off];
            if (acted) st.first.insert(a.algo);
        } else {
            reports.push_back({a.kind, a.header_off, acted ? "fixed" : "unchanged",
                               acted ? (a.algo + " recomputed over " + std::to_string(a.covered_len) + " bytes") : ""});
        }
    }

    for (const auto& kv : fit_stats) {
        uint64_t off = kv.first;
        const auto& algos = kv.second.first;
        bool sig = kv.second.second;
        if (!algos.empty()) {
            std::string list;
            for (const auto& a : algos) { if (!list.empty()) list += ","; list += a; }
            reports.push_back({"fit", off, "fixed",
                               std::to_string(algos.size()) + " hash algo(s) recomputed: " + list});
        }
        if (sig)
            reports.push_back({"fit", off, "signature-invalidated",
                               "signature over changed data; re-sign (e.g. mkimage -F -k)"});
        if (algos.empty() && !sig)
            reports.push_back({"fit", off, "unchanged", ""});
    }

    return {buf, reports};
}

}  // namespace narvi
