#include "narvi/rebuilders.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <vector>

#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "narvi/codecs.hpp"
#include "narvi/sha256.hpp"
#include "narvi/fdt.hpp"
#include "narvi/proc.hpp"

namespace fs = std::filesystem;

namespace narvi {

// --------------------------------------------------------------------------- //
// file / path / hashing
// --------------------------------------------------------------------------- //
std::string read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("cannot read " + path);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

bool file_exists(const std::string& path) {
    std::error_code ec;
    return fs::exists(path, ec);
}

std::string path_join(const std::string& a, const std::string& b) {
    return (fs::path(a) / b).string();
}

std::string sha256_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("cannot read " + path);
    Sha256 h;
    char buf[1 << 16];
    while (f) {
        f.read(buf, sizeof(buf));
        h.update(buf, (size_t)f.gcount());
    }
    return h.hex();
}

std::string hash_tree(const std::string& root) {
    Sha256 h;
    std::error_code ec;
    if (!fs::is_directory(root, ec)) {
        if (fs::exists(root, ec)) {
            h.update("F"); char z = 0; h.update(&z, 1);
            h.update(sha256_file(root));
        }
        return h.hex();
    }
    // Collect file paths, pruning nested *.extracted subtrees (those are separate
    // regions; their original bytes still live in this region's produced files).
    std::vector<std::string> rels;
    fs::recursive_directory_iterator it(
        root, fs::directory_options::skip_permission_denied, ec), end;
    for (; !ec && it != end; it.increment(ec)) {
        const fs::path& p = it->path();
        if (it->is_directory(ec)) {
            std::string name = p.filename().string();
            if (name.size() >= 10 && name.rfind(".extracted") == name.size() - 10)
                it.disable_recursion_pending();
            continue;
        }
        rels.push_back(p.lexically_relative(root).string());
    }
    std::sort(rels.begin(), rels.end());
    for (const auto& rel : rels) {
        std::string full = path_join(root, rel);
        struct stat st{};
        ::lstat(full.c_str(), &st);
        h.update("E"); char z = 0; h.update(&z, 1);
        h.update(rel);
        uint32_t mode = st.st_mode & 07777;
        h.update(&mode, sizeof(mode));
        if (S_ISLNK(st.st_mode)) {
            h.update("L");
            std::error_code lec;
            h.update(fs::read_symlink(full, lec).string());
        } else {
            h.update("R");
            h.update(sha256_file(full));
        }
    }
    return h.hex();
}

// --------------------------------------------------------------------------- //
// squashfs superblock
// --------------------------------------------------------------------------- //
static bool is_sqsh(const std::string& r) {
    return r.size() >= 4 && (r.compare(0, 4, "hsqs") == 0 || r.compare(0, 4, "sqsh") == 0);
}
long squashfs_block(const std::string& r) {
    if (r.size() < 16 || !is_sqsh(r)) return -1;
    return (uint8_t)r[12] | ((uint8_t)r[13]<<8) | ((uint8_t)r[14]<<16) | ((uint32_t)(uint8_t)r[15]<<24);
}
static const std::map<int, std::string> kSqshComp = {
    {1,"gzip"},{2,"lzma"},{3,"lzo"},{4,"xz"},{5,"lz4"},{6,"zstd"}};
std::string squashfs_comp(const std::string& r) {
    if (r.size() < 22 || !is_sqsh(r)) return "";
    int cid = (uint8_t)r[20] | ((uint8_t)r[21]<<8);
    auto it = kSqshComp.find(cid);
    return it == kSqshComp.end() ? "" : it->second;
}
long long squashfs_size(const std::string& r) {
    if (r.size() < 0x30 || !is_sqsh(r)) return -1;
    long long v = 0;
    for (int i = 0; i < 8; ++i) v |= (long long)(uint8_t)r[0x28 + i] << (8 * i);  // LE u64
    return v;
}

// --------------------------------------------------------------------------- //
// big-endian helpers
// --------------------------------------------------------------------------- //
static uint32_t rd_be32(const std::string& b, size_t off) {
    return ((uint32_t)(uint8_t)b[off] << 24) | ((uint32_t)(uint8_t)b[off+1] << 16) |
           ((uint32_t)(uint8_t)b[off+2] << 8) | (uint32_t)(uint8_t)b[off+3];
}
static void wr_be32(std::string& b, size_t off, uint32_t v) {
    b[off]=(char)(v>>24); b[off+1]=(char)(v>>16); b[off+2]=(char)(v>>8); b[off+3]=(char)v;
}

// --------------------------------------------------------------------------- //
// subprocess helpers: narvi::on_path / narvi::run (see narvi/proc.hpp)
// --------------------------------------------------------------------------- //

// --------------------------------------------------------------------------- //
// rebuilders
// --------------------------------------------------------------------------- //
class PassthroughRebuilder : public Rebuilder {
public:
    bool can_encode() const override { return false; }
    std::string encode(const Segment& s, const Working&, const RebuildContext&,
                       const std::string&) const override {
        char buf[300];
        std::snprintf(buf, sizeof(buf),
            "region %s @0x%llx needs re-encoding but no rebuilder is available for '%s'. "
            "Install a backend (e.g. squashfs-tools), revert edits to this region and "
            "anything nested in it, or supply a raw replacement.",
            s.type.c_str(), (unsigned long long)s.offset, s.type.c_str());
        throw std::runtime_error(buf);
    }
};

class CompressedRebuilder : public Rebuilder {
    static constexpr const char* PRODUCED = "decompressed";
    std::string payload(const Segment& s, const RebuildContext& c) const {
        return path_join(c.subdir_path(s), PRODUCED);
    }
public:
    std::string self_hash(const Segment& s, const RebuildContext& c) const override {
        std::string p = payload(s, c);
        return file_exists(p) ? sha256_file(p) : std::string();
    }
    std::string encode(const Segment& s, const Working& w, const RebuildContext& c,
                       const std::string&) const override {
        std::string data;
        auto it = w.find(PRODUCED);
        data = (it != w.end()) ? it->second : read_file(payload(s, c));
        int level = 9;
        auto p = s.params.find("level");
        if (p != s.params.end()) level = std::stoi(p->second);
        else if (s.type == "xz") level = 6;
        else if (s.type == "lzma") level = 6;
        else if (s.type == "zstd") level = 19;
        return compress_by_codec(s.type, data, level);
    }
};

class UImageRebuilder : public Rebuilder {
    static constexpr const char* PRODUCED = "payload";
    std::string payload_path(const Segment& s, const RebuildContext& c) const {
        return path_join(c.subdir_path(s), PRODUCED);
    }
public:
    std::string self_hash(const Segment& s, const RebuildContext& c) const override {
        std::string p = payload_path(s, c);
        return file_exists(p) ? sha256_file(p) : std::string();
    }
    std::string encode(const Segment& s, const Working& w, const RebuildContext& c,
                       const std::string& orig) const override {
        if (orig.size() < UIMAGE_HDR || rd_be32(orig, 0) != UIMAGE_MAGIC)
            throw std::runtime_error("uimage: bad or missing header");
        std::string payload;
        auto it = w.find(PRODUCED);
        payload = (it != w.end()) ? it->second : read_file(payload_path(s, c));
        std::string header = orig.substr(0, UIMAGE_HDR);
        wr_be32(header, 12, (uint32_t)payload.size());
        wr_be32(header, 24, crc32_of(payload));
        wr_be32(header, 4, 0);
        wr_be32(header, 4, crc32_of(header));
        return header + payload;
    }
};

class SquashfsRebuilder : public Rebuilder {
public:
    std::string encode(const Segment& s, const Working& w, const RebuildContext& c,
                       const std::string& orig) const override {
        if (!on_path("mksquashfs"))
            throw std::runtime_error(
                "squashfs region needs re-encoding but 'mksquashfs' is not on PATH "
                "(install squashfs-tools).");
        std::string comp = squashfs_comp(orig);
        long block = squashfs_block(orig);
        auto pc = s.params.find("compression");
        if (pc != s.params.end() && !pc->second.empty()) comp = pc->second;
        if (block <= 0) block = 131072;

        char tmpl[] = "/tmp/narvi.XXXXXX";
        if (!mkdtemp(tmpl)) throw std::runtime_error("squashfs: mkdtemp failed");
        std::string src = c.subdir_path(s);
        std::string tree = src;
        std::error_code ec;
        if (!w.empty()) {
            tree = std::string(tmpl) + "/root";
            fs::copy(src, tree, fs::copy_options::recursive |
                     fs::copy_options::copy_symlinks, ec);
            for (const auto& [rel, data] : w) {
                std::string dst = path_join(tree, rel);
                fs::create_directories(fs::path(dst).parent_path(), ec);
                std::ofstream(dst, std::ios::binary).write(data.data(), (std::streamsize)data.size());
            }
        }
        std::string out = std::string(tmpl) + "/fs.sqsh";
        std::vector<std::string> argv = {"mksquashfs", tree, out, "-noappend",
                                         "-no-progress", "-b", std::to_string(block)};
        if (!comp.empty()) { argv.push_back("-comp"); argv.push_back(comp); }
        int rc = run(argv);
        std::string blob;
        if (rc == 0) blob = read_file(out);
        fs::remove_all(tmpl, ec);
        if (rc != 0) throw std::runtime_error("mksquashfs failed (exit " + std::to_string(rc) + ")");
        return blob;
    }
};

class FitRebuilder : public Rebuilder {
    static bool supported(const std::string& comp) {
        return comp.empty() || comp == "none" || comp == "gzip" || comp == "lzma";
    }
    static std::string comp_of(const Node& sub) {
        const std::string* c = sub.get("compression");
        if (!c) return "none";
        std::string v = *c; size_t z = v.find('\0'); if (z != std::string::npos) v.resize(z);
        return v.empty() ? "none" : v;
    }
    static std::string decompress(const std::string& comp, const std::string& data, bool& ok) {
        ok = true;
        if (comp.empty() || comp == "none") return data;
        try {
            if (comp == "gzip") return gzip_decompress(data);
            if (comp == "lzma") return lzma_alone_decompress(data);
        } catch (...) { ok = false; return {}; }
        ok = false; return {};
    }
    static std::string recompress(const std::string& comp, const std::string& data) {
        if (comp.empty() || comp == "none") return data;
        if (comp == "gzip") return gzip_compress(data, 9);
        if (comp == "lzma") return lzma_alone_compress(data, 6);
        throw std::runtime_error("FIT: cannot recompress '" + comp + "'");
    }
public:
    // moria writes each subimage's *decompressed* payload to <subdir>/<name>; a
    // nested container inside one arrives in `working` under that name. Re-compress
    // only the subimages that changed (reuse original stored bytes otherwise), then
    // reserialize. Automatic re-compression covers none/gzip; other codecs are
    // refused with a pointer to rebuild_fit.
    std::string encode(const Segment& s, const Working& w, const RebuildContext& c,
                       const std::string& orig) const override {
        Fdt fdt;
        try { fdt = parse_dtb(orig, 0); }
        catch (const std::exception& e) {
            char b[128]; std::snprintf(b, sizeof(b), "fit @0x%llx: ", (unsigned long long)s.offset);
            throw std::runtime_error(std::string(b) + e.what());
        }
        Node* images = fdt.path("/images");
        if (!images) {
            char b[128]; std::snprintf(b, sizeof(b), "fit @0x%llx: no /images node", (unsigned long long)s.offset);
            throw std::runtime_error(b);
        }
        for (auto& sub : images->children) {                 // refuse unsupported codecs up front
            if (sub.get("data") && !supported(comp_of(sub))) {
                std::string msg = "fit @0x";
                char b[32]; std::snprintf(b, sizeof(b), "%llx", (unsigned long long)s.offset);
                msg += b; msg += ": subimage '" + sub.name + "' uses compression '" + comp_of(sub)
                     + "', which automatic FIT rebuild does not yet re-compress (supported: none, "
                       "gzip, lzma). Use narvi.fdt.rebuild_fit with a pre-compressed payload, or "
                       "revert edits to this FIT.";
                throw std::runtime_error(msg);
            }
        }
        std::map<std::string, std::string> edits;
        for (auto& sub : images->children) {
            const std::string* stored = sub.get("data");
            if (!stored) continue;                           // external-data subimage: left as-is
            std::string comp = comp_of(sub);
            std::string cur;
            auto it = w.find(sub.name);
            if (it != w.end()) cur = it->second;
            else {
                std::string p = path_join(c.subdir_path(s), sub.name);
                if (!file_exists(p)) continue;
                cur = read_file(p);
            }
            bool ok; std::string dec = decompress(comp, *stored, ok);
            if (!ok || cur == dec) continue;                 // unchanged: keep original stored bytes
            edits[sub.name] = recompress(comp, cur);
        }
        if (edits.empty()) return orig;
        auto res = rebuild_fit(orig, edits, 0);
        return res.first;
    }
};

// cpio (newc "070701" / crc "070702") -- initramfs/initrd archives. moria writes
// each member to <subdir>/<name>. Rebuild by walking the original archive and
// re-emitting every member in order, swapping in the on-disk bytes only for
// members whose content changed (and recomputing the 070702 data checksum).
// Headers, names, member order, the TRAILER!!! entry and any trailing padding
// are preserved from the original, so a no-edit repack is byte-identical and
// cpio needs no offset fixups -- the format stores no absolute offsets.
class CpioRebuilder : public Rebuilder {
    static uint64_t align4(uint64_t x) { return (x + 3) & ~uint64_t(3); }
    static uint64_t hex8(const std::string& s, size_t off) {
        uint64_t v = 0;
        for (size_t i = 0; i < 8; ++i) {
            char ch = s[off + i]; uint64_t d;
            if (ch >= '0' && ch <= '9') d = ch - '0';
            else if (ch >= 'a' && ch <= 'f') d = ch - 'a' + 10;
            else if (ch >= 'A' && ch <= 'F') d = ch - 'A' + 10;
            else return UINT64_MAX;
            v = v * 16 + d;
        }
        return v;
    }
    static void put_hex8(std::string& h, size_t off, uint32_t val) {
        char b[9]; std::snprintf(b, sizeof(b), "%08x", val);
        for (int i = 0; i < 8; ++i) h[off + i] = b[i];
    }
public:
    std::string encode(const Segment& s, const Working& w, const RebuildContext& c,
                       const std::string& orig) const override {
        const std::string sub = c.subdir_path(s);
        std::string out;
        size_t pos = 0, n = orig.size();
        while (pos + 110 <= n) {
            std::string magic = orig.substr(pos, 6);
            bool crc = (magic == "070702");
            if (magic != "070701" && !crc) break;                 // not a header -> tail follows
            uint64_t mode = hex8(orig, pos + 14);
            uint64_t filesize = hex8(orig, pos + 54);
            uint64_t namesize = hex8(orig, pos + 94);
            if (mode == UINT64_MAX || filesize == UINT64_MAX || namesize == UINT64_MAX || namesize == 0)
                break;
            size_t name_off = pos + 110;
            if (name_off + namesize > n) break;
            std::string name = orig.substr(name_off, namesize);
            if (auto z = name.find('\0'); z != std::string::npos) name.resize(z);
            size_t data_off = pos + (size_t)align4(110 + namesize);
            if (data_off > n || filesize > n - data_off) break;
            size_t next = data_off + (size_t)align4(filesize);

            if (name == "TRAILER!!!") break;                      // trailer + padding copied below

            std::string head = orig.substr(pos, data_off - pos);  // header + name + name padding
            std::string orig_data = orig.substr(data_off, (size_t)filesize);
            uint32_t type = (uint32_t)mode & 0170000;

            // The member's current bytes: a rebuilt nested child wins, else read
            // from disk by type, else fall back to the original bytes.
            std::string data;
            bool have_new = false;
            if (auto it = w.find(name); it != w.end()) { data = it->second; have_new = true; }
            else {
                std::string p = path_join(sub, name);
                if (type == 0120000) {                            // symlink: data is the target
                    std::error_code ec;
                    auto tgt = std::filesystem::read_symlink(p, ec);
                    if (!ec) { data = tgt.string(); have_new = true; }
                } else if (type == 0100000) {                     // regular file
                    if (file_exists(p)) { data = read_file(p); have_new = true; }
                }
                // directories and other types carry no data
            }
            if (!have_new) data = orig_data;

            if (data == orig_data) {
                out += head; out += orig_data;                    // unchanged: verbatim
                out.append((size_t)align4(filesize) - (size_t)filesize, '\0');
            } else {
                put_hex8(head, 54, (uint32_t)data.size());        // c_filesize
                if (crc) {                                        // c_check (offset 102) = sum of data bytes
                    uint32_t sum = 0; for (unsigned char ch : data) sum += ch;
                    put_hex8(head, 102, sum);
                }
                out += head; out += data;
                out.append((size_t)align4(data.size()) - data.size(), '\0');
            }
            if (next <= pos) break;
            pos = next;
        }
        out += orig.substr(pos);     // TRAILER!!! entry + any trailing block padding, verbatim
        return out;
    }
};

const Rebuilder& rebuilder_for(const std::string& type) {
    static const CompressedRebuilder compressed;
    static const UImageRebuilder uimage;
    static const SquashfsRebuilder squashfs;
    static const FitRebuilder fit;
    static const CpioRebuilder cpio;
    static const PassthroughRebuilder passthrough;
    if (type == "gzip" || type == "lzma" || type == "xz" || type == "zstd" || type == "lz4") return compressed;
    if (type == "uimage") return uimage;
    if (type == "squashfs") return squashfs;
    if (type == "fit") return fit;
    if (type == "cpio") return cpio;
    return passthrough;
}

}  // namespace narvi
