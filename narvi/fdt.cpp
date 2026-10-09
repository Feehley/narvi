// fdt.cpp -- minimal FDT/FIT struct-block walker (see fdt.hpp).
#include "narvi/fdt.hpp"

#include <algorithm>
#include <functional>

namespace narvi {

namespace {
constexpr uint32_t BEGIN_NODE = 1, END_NODE = 2, PROP = 3, NOP = 4, END = 9;
constexpr size_t MAX_TOKENS = 4u << 20;

uint32_t u32be(const std::string& b, size_t o) {
    return ((uint32_t)(uint8_t)b[o] << 24) | ((uint32_t)(uint8_t)b[o+1] << 16) |
           ((uint32_t)(uint8_t)b[o+2] << 8) | (uint32_t)(uint8_t)b[o+3];
}
uint64_t align4(uint64_t v) { return (v + 3) & ~uint64_t(3); }

struct Frame {
    std::string name;
    bool is_sub = false, is_hash = false, is_sig = false;
    long long data_off = -1, data_len = -1;
    long long ext_off = -1, ext_pos = -1, ext_size = -1;
    std::string algo;
    long long value_off = -1, value_len = -1;
};

std::string cstr(const std::string& img, uint64_t p, uint64_t limit, uint64_t& next) {
    std::string s;
    while (p < limit && img[p] != 0) { s.push_back(img[p]); ++p; }
    next = p + 1;
    return s;
}

void resolve_payload(const Frame& sub, uint64_t fit_off, uint64_t totalsize,
                     long long& off, long long& len) {
    if (sub.data_off >= 0) { off = sub.data_off; len = sub.data_len; return; }
    if (sub.ext_pos >= 0 && sub.ext_size >= 0) { off = (long long)fit_off + sub.ext_pos; len = sub.ext_size; return; }
    if (sub.ext_off >= 0 && sub.ext_size >= 0) {
        off = (long long)(fit_off + align4(totalsize)) + sub.ext_off; len = sub.ext_size; return;
    }
    off = -1; len = 0;
}
}  // namespace

FitLayout parse_fit(const std::string& image, uint64_t off) {
    FitLayout out;
    uint64_t n = image.size();
    if (off + 40 > n || u32be(image, off) != FDT_MAGIC) return out;
    uint64_t totalsize = u32be(image, off + 4);
    uint64_t off_struct = u32be(image, off + 8);
    uint64_t off_strings = u32be(image, off + 12);
    uint64_t size_strings = u32be(image, off + 32);
    uint64_t size_struct = u32be(image, off + 36);
    uint64_t struct_off = off + off_struct;
    uint64_t strings_off = off + off_strings;
    uint64_t end = std::min(off + totalsize, n);
    uint64_t struct_end = std::min(struct_off + size_struct, end);
    uint64_t strings_end = std::min(strings_off + size_strings, end);
    if (!(off_struct > 0 && struct_off < n && struct_off <= struct_end)) return out;

    out.ok = true;
    out.geom = {totalsize, off_struct, size_struct, off_strings, size_strings};

    auto propname = [&](uint64_t nameoff) -> std::string {
        uint64_t p = strings_off + nameoff, next;
        if (p >= strings_end) return "";
        return cstr(image, p, strings_end, next);
    };

    std::vector<Frame> stack;
    uint64_t p = struct_off;
    size_t tokens = 0;
    while (p + 4 <= struct_end && tokens < MAX_TOKENS) {
        ++tokens;
        uint32_t tok = u32be(image, p);
        p += 4;
        if (tok == NOP) continue;
        if (tok == END) break;
        if (tok == BEGIN_NODE) {
            uint64_t next;
            std::string name = cstr(image, p, struct_end, next);
            p = align4(next);
            size_t depth = stack.size();
            const Frame* parent = stack.empty() ? nullptr : &stack.back();
            bool is_sub = depth == 2 && stack.size() >= 2 && stack[1].name == "images";
            bool is_hash = depth == 3 && parent && parent->is_sub && name.rfind("hash", 0) == 0;
            bool is_sig = depth == 3 && parent && parent->is_sub && name.rfind("signature", 0) == 0;
            Frame f; f.name = name; f.is_sub = is_sub; f.is_hash = is_hash; f.is_sig = is_sig;
            stack.push_back(f);
            continue;
        }
        if (tok == PROP) {
            if (p + 8 > struct_end) break;
            uint32_t plen = u32be(image, p);
            uint32_t nameoff = u32be(image, p + 4);
            p += 8;
            uint64_t val_off = p;
            p = align4(p + plen);
            if (stack.empty()) continue;
            Frame& fr = stack.back();
            std::string pname = propname(nameoff);
            if (fr.is_sub) {
                if (pname == "data") { fr.data_off = (long long)val_off; fr.data_len = plen; }
                else if (pname == "data-offset" && plen == 4) fr.ext_off = u32be(image, val_off);
                else if (pname == "data-position" && plen == 4) fr.ext_pos = u32be(image, val_off);
                else if (pname == "data-size" && plen == 4) fr.ext_size = u32be(image, val_off);
            } else if (fr.is_hash || fr.is_sig) {
                if (pname == "algo") {
                    std::string a(image.substr(val_off, plen));
                    size_t z = a.find('\0');
                    if (z != std::string::npos) a.resize(z);
                    fr.algo = a;
                } else if (pname == "value") {
                    fr.value_off = (long long)val_off; fr.value_len = plen;
                }
            }
            continue;
        }
        if (tok == END_NODE) {
            if (stack.empty()) break;
            Frame fr = stack.back();
            stack.pop_back();
            const Frame* parent = stack.empty() ? nullptr : &stack.back();
            if ((fr.is_hash || fr.is_sig) && parent && parent->is_sub) {
                long long poff, plen;
                resolve_payload(*parent, off, totalsize, poff, plen);
                if (poff >= 0 && (uint64_t)(poff + plen) <= n) {
                    if (fr.is_hash && !fr.algo.empty() && fr.value_off >= 0)
                        out.hashes.push_back({fr.algo, (uint64_t)poff, (uint64_t)plen,
                                              (uint64_t)fr.value_off, (uint64_t)fr.value_len});
                    else if (fr.is_sig)
                        out.sigs.push_back({(uint64_t)poff, (uint64_t)plen});
                }
            }
            continue;
        }
        break;  // unknown token
    }
    return out;
}

}  // namespace narvi


// =========================================================================== //
// Tree model + serializer + FIT rebuild.
// =========================================================================== //
#include <stdexcept>

#include "narvi/codecs.hpp"   // crc32_of
#include "narvi/md5.hpp"
#include "narvi/sha1.hpp"
#include "narvi/sha256.hpp"

namespace narvi {

namespace {
std::string pad_bytes(const std::string& b) {
    return b + std::string((4 - b.size() % 4) % 4, '\0');
}
std::string be32s(uint32_t v) {
    std::string s(4, '\0');
    for (int i = 0; i < 4; i++) s[i] = (char)(uint8_t)(v >> (8 * (3 - i)));
    return s;
}
std::string sha256_raw_(const std::string& d) {
    std::string hex = sha256_hex(d), raw(hex.size() / 2, '\0');
    auto nyb = [](char c){ return (c>='0'&&c<='9')?c-'0':(c>='a'&&c<='f')?c-'a'+10:0; };
    for (size_t i = 0; i < raw.size(); i++) raw[i] = (char)((nyb(hex[2*i])<<4)|nyb(hex[2*i+1]));
    return raw;
}
std::string fit_digest(const std::string& algo, const std::string& data) {
    if (algo == "crc32") return be32s(crc32_of(data));   // FIT stores crc32 big-endian
    if (algo == "md5") return md5_bytes(data);
    if (algo == "sha1") return sha1_bytes(data);
    if (algo == "sha256") return sha256_raw_(data);
    return std::string();
}
std::string first_cstr(const std::string& v) {
    size_t z = v.find('\0');
    return z == std::string::npos ? v : v.substr(0, z);
}
}  // namespace

Prop* Node::prop(const std::string& n) {
    for (auto& p : props) if (p.name == n) return &p;
    return nullptr;
}
const std::string* Node::get(const std::string& n) const {
    for (auto& p : props) if (p.name == n) return &p.value;
    return nullptr;
}
void Node::set(const std::string& n, const std::string& v) {
    for (auto& p : props) if (p.name == n) { p.value = v; return; }
    props.push_back({n, v, -1});
}
Node* Node::child(const std::string& n) {
    for (auto& c : children) if (c.name == n) return &c;
    return nullptr;
}

Node* Fdt::path(const std::string& p) {
    Node* node = &root;
    size_t i = 0;
    while (i < p.size()) {
        while (i < p.size() && p[i] == '/') ++i;
        size_t j = i;
        while (j < p.size() && p[j] != '/') ++j;
        if (j > i) {
            node = node ? node->child(p.substr(i, j - i)) : nullptr;
            if (!node) return nullptr;
        }
        i = j;
    }
    return node;
}

std::string Fdt::to_bytes() const {
    std::string strtab = this->strings;
    std::map<std::string, uint32_t> appended;

    auto nameoff = [&](const Prop& pr) -> uint32_t {
        if (pr.nameoff >= 0) return (uint32_t)pr.nameoff;
        auto it = appended.find(pr.name);
        if (it != appended.end()) return it->second;
        uint32_t off = (uint32_t)strtab.size();
        strtab += pr.name; strtab.push_back('\0');
        appended[pr.name] = off;
        return off;
    };

    std::string body;
    std::function<void(const Node&)> emit = [&](const Node& node) {
        body += be32s(1);                                  // BEGIN_NODE
        body += pad_bytes(node.name + std::string(1, '\0'));
        for (const auto& pr : node.props) {
            body += be32s(3);                              // PROP
            body += be32s((uint32_t)pr.value.size());
            body += be32s(nameoff(pr));
            body += pad_bytes(pr.value);
        }
        for (const auto& c : node.children) emit(c);
        body += be32s(2);                                  // END_NODE
    };
    emit(root);
    body += be32s(9);                                      // END

    uint32_t off_struct = 40 + (uint32_t)pre_struct.size();
    uint32_t size_struct = (uint32_t)body.size();
    uint32_t off_strings = off_struct + size_struct;
    uint32_t size_strings = (uint32_t)strtab.size();
    uint32_t total = off_strings + size_strings;
    std::string hdr = be32s(FDT_MAGIC) + be32s(total) + be32s(off_struct) + be32s(off_strings)
                    + be32s(off_mem_rsvmap) + be32s(version) + be32s(last_comp_version)
                    + be32s(boot_cpuid_phys) + be32s(size_strings) + be32s(size_struct);
    return hdr + pre_struct + body + strtab;
}

Fdt parse_dtb(const std::string& image, uint64_t off) {
    uint64_t n = image.size();
    if (off + 40 > n || u32be(image, off) != FDT_MAGIC)
        throw std::runtime_error("not an FDT (bad magic)");
    uint64_t totalsize = u32be(image, off + 4);
    uint64_t off_struct = u32be(image, off + 8);
    uint64_t off_strings = u32be(image, off + 12);
    uint32_t off_mem = u32be(image, off + 16);
    uint32_t version = u32be(image, off + 20);
    uint32_t last_comp = u32be(image, off + 24);
    uint32_t boot_cpuid = u32be(image, off + 28);
    uint64_t size_strings = u32be(image, off + 32);
    uint64_t size_struct = u32be(image, off + 36);
    uint64_t struct_off = off + off_struct;
    uint64_t struct_end = std::min(std::min(struct_off + size_struct, off + totalsize), n);
    uint64_t strings_off = off + off_strings;
    uint64_t strings_end = std::min(std::min(strings_off + size_strings, off + totalsize), n);
    if (!(off_struct > 0 && off_struct <= off_strings) || struct_off > n)
        throw std::runtime_error("unsupported FDT layout");

    Fdt f;
    f.pre_struct = image.substr(off + 40, struct_off - (off + 40));
    f.strings = image.substr(strings_off, strings_end - strings_off);
    f.off_mem_rsvmap = off_mem;
    f.version = version;
    f.last_comp_version = last_comp;
    f.boot_cpuid_phys = boot_cpuid;

    auto propname = [&](uint64_t nameoff) -> std::string {
        uint64_t p = strings_off + nameoff, next;
        if (p >= strings_end) return "";
        return cstr(image, p, strings_end, next);
    };

    std::vector<Node*> stack;
    Node* root_done = nullptr;
    // Use a holder so Node pointers into children vectors stay valid: we build
    // the tree by appending children to their parent and tracking pointers, and
    // never resize a vector whose element is on the stack above the current top.
    // To keep pointers stable across child appends we reserve generously.
    std::function<Node*(Node*)> push_child = [&](Node* parent) -> Node* {
        parent->children.reserve(parent->children.size() + 8);
        parent->children.push_back(Node{});
        return &parent->children.back();
    };

    uint64_t p = struct_off;
    size_t tokens = 0;
    while (p + 4 <= struct_end && tokens < MAX_TOKENS) {
        ++tokens;
        uint32_t tok = u32be(image, p);
        p += 4;
        if (tok == NOP) continue;
        if (tok == END) break;
        if (tok == BEGIN_NODE) {
            uint64_t next;
            std::string name = cstr(image, p, struct_end, next);
            p = align4(next);
            Node* node;
            if (stack.empty()) { f.root = Node{}; f.root.name = name; node = &f.root; }
            else { node = push_child(stack.back()); node->name = name; }
            stack.push_back(node);
        } else if (tok == PROP) {
            if (p + 8 > struct_end) break;
            uint32_t plen = u32be(image, p);
            uint32_t nameoff = u32be(image, p + 4);
            p += 8;
            std::string val = image.substr(p, plen);
            p = align4(p + plen);
            if (!stack.empty()) stack.back()->props.push_back({propname(nameoff), val, (long long)nameoff});
        } else if (tok == END_NODE) {
            if (stack.empty()) break;
            root_done = stack.front();
            stack.pop_back();
        } else {
            throw std::runtime_error("unknown FDT token");
        }
    }
    (void)root_done;
    return f;
}

std::pair<std::string, FitRebuildReport>
rebuild_fit(const std::string& fit, const std::map<std::string, std::string>& edits, uint64_t off) {
    Fdt f = parse_dtb(fit, off);
    FitRebuildReport rep;
    Node* images = f.root.child("images");
    if (!images) return {f.to_bytes(), rep};

    for (auto& sub : images->children) {
        bool edited = edits.count(sub.name) > 0;
        if (edited) {
            if (!sub.prop("data")) {
                rep.external_skipped.push_back(sub.name);
                edited = false;
            } else {
                const std::string* oldp = sub.get("data");
                std::string oldv = oldp ? *oldp : std::string();
                const std::string& nv = edits.at(sub.name);
                if (oldv.size() != nv.size())
                    rep.resized.emplace_back(sub.name, (uint64_t)oldv.size(), (uint64_t)nv.size());
                sub.set("data", nv);
                if (sub.prop("data-size")) sub.set("data-size", be32s((uint32_t)nv.size()));
            }
        }
        const std::string* stored = sub.get("data");
        if (!stored) continue;
        for (auto& c : sub.children) {
            if (c.name.rfind("hash", 0) == 0) {
                const std::string* a = c.get("algo");
                std::string algo = a ? first_cstr(*a) : "";
                std::string d = fit_digest(algo, *stored);
                if (!d.empty()) { c.set("value", d); rep.hashes.emplace_back(sub.name, algo); }
            } else if (c.name.rfind("signature", 0) == 0 && edited) {
                rep.invalidated_sigs.push_back(sub.name);
            }
        }
    }
    return {f.to_bytes(), rep};
}

}  // namespace narvi
