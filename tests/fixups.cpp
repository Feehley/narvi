// fixups.cpp -- tests for container checksum fixups: TRX/Seama/U-Boot-env
// recompute, the validate-on-original safety rule, nested wrappers, FIT
// flagging, and an end-to-end repack that repairs an outer TRX CRC after an
// inner edit.
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#include "narvi/codecs.hpp"
#include "narvi/fixups.hpp"
#include "narvi/md5.hpp"
#include "narvi/model.hpp"
#include "narvi/recipe.hpp"
#include "narvi/repacker.hpp"
#include "tests/fixture.hpp"

using namespace narvi;

static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { std::cerr << "FAIL: " << msg << "\n"; ++failures; } } while (0)

// -------- little/big-endian pack + read helpers --------
static std::string le32(uint32_t v) {
    std::string s(4, '\0'); for (int i = 0; i < 4; i++) s[i] = (char)(uint8_t)(v >> (8 * i)); return s;
}
static std::string be16(uint16_t v) { std::string s(2, '\0'); s[0] = (char)(v >> 8); s[1] = (char)v; return s; }
static std::string be32(uint32_t v) {
    std::string s(4, '\0'); for (int i = 0; i < 4; i++) s[i] = (char)(uint8_t)(v >> (8 * (3 - i))); return s;
}
static uint32_t rd_le32(const std::string& b, size_t o) {
    return (uint32_t)(uint8_t)b[o] | ((uint32_t)(uint8_t)b[o+1] << 8) |
           ((uint32_t)(uint8_t)b[o+2] << 16) | ((uint32_t)(uint8_t)b[o+3] << 24);
}
static uint32_t rd_be16(const std::string& b, size_t o) {
    return ((uint32_t)(uint8_t)b[o] << 8) | (uint32_t)(uint8_t)b[o+1];
}
static uint32_t rd_be32(const std::string& b, size_t o) {
    return ((uint32_t)(uint8_t)b[o] << 24) | ((uint32_t)(uint8_t)b[o+1] << 16) |
           ((uint32_t)(uint8_t)b[o+2] << 8) | (uint32_t)(uint8_t)b[o+3];
}

// -------- wrapper builders --------
static std::string make_trx(const std::string& payload) {
    uint32_t total = 28 + (uint32_t)payload.size();
    std::string body = le32(0x00010000) + le32(28) + le32(28) + le32(28) + payload;
    uint32_t crc = crc32_of(body);
    return std::string("HDR0") + le32(total) + le32(crc) + body;
}
static std::string make_env(const std::vector<std::string>& pairs,
                            uint32_t env_size = 0x2000, bool redundant = false) {
    std::string data;
    for (const auto& p : pairs) { data += p; data.push_back('\0'); }
    data.push_back('\0');
    size_t hlen = redundant ? 5 : 4;
    data.append(env_size - hlen - data.size(), '\0');
    uint32_t crc = crc32_of(data);
    std::string head = le32(crc);
    if (redundant) head.push_back('\x01');
    return head + data;
}
static std::string make_seama(const std::string& metadata, const std::string& image) {
    std::string body = metadata + image;
    std::string md5 = md5_bytes(body);
    std::string hdr = std::string("\x5e\xa3\xa4\x17", 4) + be16(0) + be16((uint16_t)metadata.size())
                    + be32((uint32_t)image.size());
    return hdr + md5 + body;
}
// -------- FIT builder + digest helpers --------
#include "narvi/md5.hpp"
#include "narvi/sha1.hpp"
#include "narvi/sha256.hpp"

static std::string sha256_raw(const std::string& d) {
    std::string hex = sha256_hex(d), raw(hex.size() / 2, '\0');
    auto nyb = [](char c){ return (c>='0'&&c<='9')?c-'0':(c>='a'&&c<='f')?c-'a'+10:0; };
    for (size_t i = 0; i < raw.size(); i++) raw[i] = (char)((nyb(hex[2*i])<<4)|nyb(hex[2*i+1]));
    return raw;
}
static std::string fit_hash(const std::string& algo, const std::string& d) {
    if (algo == "crc32") return be32(crc32_of(d));      // FIT stores crc32 big-endian
    if (algo == "md5") return md5_bytes(d);
    if (algo == "sha1") return sha1_bytes(d);
    return sha256_raw(d);
}
static std::string pad4(const std::string& b) { return b + std::string((4 - b.size() % 4) % 4, '\0'); }

struct FitImage { std::string name, data; std::vector<std::pair<std::string,std::string>> hashes; bool sig; };
struct BuiltFit {
    std::string bytes;
    std::map<std::string, std::pair<uint64_t,uint64_t>> data_abs;
    std::map<std::string, std::pair<uint64_t,uint64_t>> hash_abs;   // key "name|algo"
};

static BuiltFit build_fit(const std::vector<FitImage>& images) {
    std::string strings;
    std::map<std::string, uint32_t> soff;
    auto S = [&](const std::string& name) -> uint32_t {
        auto it = soff.find(name);
        if (it != soff.end()) return it->second;
        uint32_t o = (uint32_t)strings.size(); soff[name] = o; strings += name; strings.push_back('\0'); return o;
    };
    std::string buf;
    auto tok = [&](uint32_t v){ buf += be32(v); };
    auto begin = [&](const std::string& name){ tok(1); buf += pad4(name + std::string(1,'\0')); };
    auto endn = [&](){ tok(2); };
    std::map<std::string, std::pair<uint64_t,uint64_t>> data_pos, hash_pos;
    auto prop = [&](const std::string& name, const std::string& value) -> std::pair<uint64_t,uint64_t> {
        tok(3); buf += be32((uint32_t)value.size()); buf += be32(S(name));
        uint64_t off = buf.size(); buf += pad4(value); return {off, value.size()};
    };
    begin("");
    prop("timestamp", be32(0));
    begin("images");
    for (const auto& im : images) {
        begin(im.name);
        prop("type", std::string("kernel\0", 7));
        prop("compression", std::string("none\0", 5));
        auto d = prop("data", im.data);
        data_pos[im.name] = d;
        int i = 0;
        for (const auto& h : im.hashes) {
            begin("hash-" + std::to_string(++i));
            prop("algo", h.first + std::string(1, '\0'));
            auto v = prop("value", h.second);
            hash_pos[im.name + "|" + h.first] = v;
            endn();
        }
        if (im.sig) {
            begin("signature-1");
            prop("algo", std::string("sha256,rsa2048\0", 15));
            prop("value", std::string(256, '\0'));
            endn();
        }
        endn();
    }
    endn();                     // images
    begin("configurations");
    prop("default", std::string("conf-1\0", 7));
    endn();
    endn();                     // root
    tok(9);

    std::string struct_block = buf;
    std::string rsv(16, '\0');
    uint32_t off_mem = 40, off_struct = off_mem + (uint32_t)rsv.size();
    uint32_t off_strings = off_struct + (uint32_t)struct_block.size();
    uint32_t total = off_strings + (uint32_t)strings.size();
    std::string hdr = be32(0xd00dfeed) + be32(total) + be32(off_struct) + be32(off_strings)
                    + be32(off_mem) + be32(17) + be32(16) + be32(0)
                    + be32((uint32_t)strings.size()) + be32((uint32_t)struct_block.size());
    BuiltFit bf;
    bf.bytes = hdr + rsv + struct_block + strings;
    for (auto& kv : data_pos) bf.data_abs[kv.first] = {off_struct + kv.second.first, kv.second.second};
    for (auto& kv : hash_pos) bf.hash_abs[kv.first] = {off_struct + kv.second.first, kv.second.second};
    return bf;
}

static std::string edit_payload(const std::string& fit, uint64_t off, uint64_t len, uint8_t nb) {
    std::string m = fit;
    for (uint64_t i = off; i < off + len; i++) m[i] = (char)nb;
    return m;
}
static std::string flip(const std::string& b, size_t off) {
    std::string m = b; m[off] = (char)(uint8_t)(m[off] ^ 0xFF); return m;
}

// -------- TRX --------
static void test_trx_fixed_on_change() {
    std::string orig = make_trx("kernel payload here, several bytes");
    uint32_t total = rd_le32(orig, 4);
    auto [out, reps] = apply_fixups(orig, flip(orig, 40), {});
    CHECK(reps.size() == 1 && reps[0].kind == "trx" && reps[0].status == "fixed", "trx fixed");
    CHECK(rd_le32(out, 8) == crc32_of(out.substr(12, total - 12)), "trx crc valid");
}
static void test_trx_noop() {
    std::string orig = make_trx("unchanging payload");
    auto [out, reps] = apply_fixups(orig, orig, {});
    CHECK(out == orig, "trx noop bytes");
    CHECK(reps.size() == 1 && reps[0].status == "unchanged", "trx noop status");
}
static void test_trx_not_fixed_if_invalid() {
    std::string orig = make_trx("payload bytes here, enough to flip");
    orig[8] = (char)(uint8_t)(orig[8] ^ 0xFF);       // break stored crc
    std::string edited = flip(orig, 40);
    auto [out, reps] = apply_fixups(orig, edited, {});
    CHECK(reps.empty(), "invalid trx: no fixup");
    CHECK(out == edited, "invalid trx: untouched");
}

// -------- U-Boot env --------
static void test_uboot_env_fixed() {
    std::string env = make_env({"bootcmd=run boot", "bootdelay=2", "baudrate=115200"});
    Segment seg; seg.offset = 0; seg.length = env.size(); seg.kind = Kind::Region; seg.type = "uboot_env";
    auto [out, reps] = apply_fixups(env, flip(env, 200), {seg});
    CHECK(reps.size() == 1 && reps[0].kind == "uboot_env" && reps[0].status == "fixed", "env fixed");
    CHECK(rd_le32(out, 0) == crc32_of(out.substr(4, env.size() - 4)), "env crc valid");
}
static void test_uboot_env_redundant() {
    std::string env = make_env({"bootcmd=boot", "x=y"}, 0x2000, true);
    Segment seg; seg.offset = 0; seg.length = env.size(); seg.kind = Kind::Region; seg.type = "uboot_env";
    auto [out, reps] = apply_fixups(env, flip(env, 300), {seg});
    CHECK(reps.size() == 1 && reps[0].status == "fixed", "redundant env fixed");
    CHECK(rd_le32(out, 0) == crc32_of(out.substr(5, env.size() - 5)), "redundant env crc valid");
}

// -------- Seama --------
static void test_seama_fixed() {
    std::string orig = make_seama("meta", "image body bytes, several of them");
    auto [out, reps] = apply_fixups(orig, flip(orig, 40), {});
    CHECK(reps.size() == 1 && reps[0].kind == "seama" && reps[0].status == "fixed", "seama fixed");
    uint32_t metasize = rd_be16(out, 6), size = rd_be32(out, 8);
    CHECK(out.substr(12, 16) == md5_bytes(out.substr(28, metasize + size)), "seama md5 valid");
}

// -------- FIT --------
static void test_fit_hash_recomputed_sha256() {
    std::string payload; for (int i = 0; i < 3; i++) payload += "kernel image bytes, several here ";
    BuiltFit bf = build_fit({{"kernel", payload, {{"sha256", fit_hash("sha256", payload)}}, false}});
    auto [doff, dlen] = bf.data_abs["kernel"];
    auto [out, reps] = apply_fixups(bf.bytes, edit_payload(bf.bytes, doff, dlen, 0x5A), {});
    bool fixed = false; for (auto& r : reps) if (r.kind == "fit" && r.status == "fixed") fixed = true;
    CHECK(fixed, "fit sha256 fixed");
    auto [voff, vlen] = bf.hash_abs["kernel|sha256"];
    CHECK(out.substr(voff, vlen) == sha256_raw(out.substr(doff, dlen)), "fit sha256 value valid");
}
static void test_fit_crc32_and_sha1() {
    std::string payload; for (int i = 0; i < 4; i++) payload += "another kernel payload block ";
    for (std::string algo : {std::string("crc32"), std::string("sha1")}) {
        BuiltFit bf = build_fit({{"k", payload, {{algo, fit_hash(algo, payload)}}, false}});
        auto [doff, dlen] = bf.data_abs["k"];
        auto [out, reps] = apply_fixups(bf.bytes, edit_payload(bf.bytes, doff, dlen, 0x11), {});
        bool fixed = false; for (auto& r : reps) if (r.kind == "fit" && r.status == "fixed") fixed = true;
        CHECK(fixed, "fit " + algo + " fixed");
        auto [voff, vlen] = bf.hash_abs["k|" + algo];
        CHECK(out.substr(voff, vlen) == fit_hash(algo, out.substr(doff, dlen)), "fit " + algo + " valid");
    }
}
static void test_fit_multiple_algos() {
    std::string payload; for (int i = 0; i < 5; i++) payload += "multi-hash kernel ";
    BuiltFit bf = build_fit({{"kernel", payload,
        {{"crc32", fit_hash("crc32", payload)}, {"sha256", fit_hash("sha256", payload)}}, false}});
    auto [doff, dlen] = bf.data_abs["kernel"];
    auto [out, reps] = apply_fixups(bf.bytes, edit_payload(bf.bytes, doff, dlen, 0x22), {});
    bool ok = false;
    for (auto& r : reps)
        if (r.kind == "fit" && r.status == "fixed" &&
            r.detail.find("crc32") != std::string::npos && r.detail.find("sha256") != std::string::npos) ok = true;
    CHECK(ok, "fit multi-algo reported together");
    for (std::string algo : {std::string("crc32"), std::string("sha256")}) {
        auto [voff, vlen] = bf.hash_abs["kernel|" + algo];
        CHECK(out.substr(voff, vlen) == fit_hash(algo, out.substr(doff, dlen)), "fit multi " + algo + " valid");
    }
}
static void test_fit_unchanged_quiet() {
    std::string payload; for (int i = 0; i < 4; i++) payload += "steady kernel bytes ";
    BuiltFit bf = build_fit({{"kernel", payload, {{"sha256", fit_hash("sha256", payload)}}, false}});
    auto [out, reps] = apply_fixups(bf.bytes, bf.bytes, {});
    CHECK(out == bf.bytes, "fit unchanged bytes");
    CHECK(reps.size() == 1 && reps[0].status == "unchanged", "fit unchanged quiet");
}
static void test_fit_signature_flagged() {
    std::string payload; for (int i = 0; i < 4; i++) payload += "signed kernel bytes ";
    BuiltFit bf = build_fit({{"kernel", payload, {{"sha256", fit_hash("sha256", payload)}}, true}});
    auto [doff, dlen] = bf.data_abs["kernel"];
    auto [out, reps] = apply_fixups(bf.bytes, edit_payload(bf.bytes, doff, dlen, 0x33), {});
    bool fixed = false, sig = false;
    for (auto& r : reps) {
        if (r.kind == "fit" && r.status == "fixed") fixed = true;
        if (r.kind == "fit" && r.status == "signature-invalidated") sig = true;
    }
    CHECK(fixed && sig, "fit hash fixed + signature flagged");
}
static void test_fit_not_recomputed_if_invalid() {
    std::string payload; for (int i = 0; i < 3; i++) payload += "kernel with a bad stored hash ";
    std::string bad(32, '\0');
    BuiltFit bf = build_fit({{"kernel", payload, {{"sha256", bad}}, false}});
    auto [doff, dlen] = bf.data_abs["kernel"];
    auto [out, reps] = apply_fixups(bf.bytes, edit_payload(bf.bytes, doff, dlen, 0x44), {});
    bool any_fixed = false; for (auto& r : reps) if (r.status == "fixed") any_fixed = true;
    CHECK(!any_fixed, "invalid original: not recomputed");
    auto [voff, vlen] = bf.hash_abs["kernel|sha256"];
    CHECK(out.substr(voff, vlen) == bad, "invalid original: value untouched");
}
static void test_plain_dtb_not_flagged() {
    std::string payload; for (int i = 0; i < 4; i++) payload += "just data ";
    BuiltFit bf = build_fit({{"blob", payload, {}, false}});   // no hash/sig nodes
    auto [doff, dlen] = bf.data_abs["blob"];
    auto [out, reps] = apply_fixups(bf.bytes, edit_payload(bf.bytes, doff, dlen, 0x55), {});
    CHECK(reps.empty(), "plain dtb without hashes not flagged");
}

// -------- nested --------
static void test_nested_inner_then_outer() {
    std::string env = make_env({"bootcmd=boot", "ver=1"}, 0x1000);
    std::string prefix(16, (char)0xAA);
    std::string trx = make_trx(prefix + env);
    uint64_t env_abs = 28 + prefix.size();
    Segment seg; seg.offset = env_abs; seg.length = env.size(); seg.kind = Kind::Region; seg.type = "uboot_env";
    auto [out, reps] = apply_fixups(trx, flip(trx, env_abs + 100), {seg});
    bool trx_fixed = false, env_fixed = false;
    for (const auto& r : reps) {
        if (r.kind == "trx" && r.status == "fixed") trx_fixed = true;
        if (r.kind == "uboot_env" && r.status == "fixed") env_fixed = true;
    }
    CHECK(trx_fixed && env_fixed, "both wrappers fixed");
    CHECK(rd_le32(out, env_abs) == crc32_of(out.substr(env_abs + 4, env.size() - 4)), "inner env crc valid");
    uint32_t total = rd_le32(out, 4);
    CHECK(rd_le32(out, 8) == crc32_of(out.substr(12, total - 12)), "outer trx crc valid");
}

// -------- end-to-end --------
struct TrxSandbox { std::string image, kernel, gz; uint64_t gz_off; std::string image_path, ext, idj; };

static TrxSandbox build_trx_gzip_sandbox(const std::string& td) {
    TrxSandbox s;
    for (int i = 0; i < 40; i++) s.kernel += "inner kernel, compressible ";
    s.gz = gzip_compress(s.kernel, 9);
    std::string trx = make_trx(s.gz);
    std::string image = trx;
    image.append(0x4000 - image.size(), (char)0xff);
    s.image = image;
    s.gz_off = 28;
    s.image_path = (std::filesystem::path(td) / "firmware.bin").string();
    fixture::write_file(s.image_path, image);
    s.ext = s.image_path + ".extracted";
    fixture::write_file(s.ext + "/0x1c-gzip/decompressed", s.kernel);
    std::string manifest = std::string("{\"source\":\"") + s.image_path +
        "\",\"extracted\":[{\"offset\":28,\"type\":\"gzip\",\"root\":\"0x1c-gzip\",\"status\":\"ok\",\"depth\":1}]}";
    fixture::write_file(s.ext + "/manifest.json", manifest);
    std::string identify = std::string("{\"findings\":[{\"offset\":28,\"size\":") +
        std::to_string(s.gz.size()) + ",\"type\":\"gzip\",\"compression\":\"gzip\"}]}";
    s.idj = (std::filesystem::path(td) / "identify.json").string();
    fixture::write_file(s.idj, identify);
    return s;
}

static void test_end_to_end_trx_fixed() {
    std::string td = fixture::mktemp_dir();
    TrxSandbox s = build_trx_gzip_sandbox(td);
    Recipe r = Recipe::from_extraction(s.image_path, s.ext, s.idj);
    // Edit innermost kernel (zeros compress smaller -> fits slot).
    fixture::write_file(s.ext + "/0x1c-gzip/decompressed", std::string(s.kernel.size(), '\0'));
    std::string out = (std::filesystem::path(td) / "out.bin").string();
    RepackReport rep = Repacker(r).repack(out);
    bool trx_fixed = false;
    for (const auto& f : rep.fixups) if (f.kind == "trx" && f.status == "fixed") trx_fixed = true;
    CHECK(trx_fixed, "end-to-end trx fixed reported");
    std::string blob = fixture::slurp(out);
    uint32_t total = rd_le32(blob, 4);
    CHECK(rd_le32(blob, 8) == crc32_of(blob.substr(12, total - 12)), "end-to-end trx crc valid");
    // With fixups off, the CRC is left stale.
    std::string out2 = (std::filesystem::path(td) / "out2.bin").string();
    Repacker(r).repack(out2, "fixed", /*do_fixups=*/false);
    std::string blob2 = fixture::slurp(out2);
    CHECK(rd_le32(blob2, 8) != crc32_of(blob2.substr(12, total - 12)), "no-fixups leaves crc stale");
    std::filesystem::remove_all(td);
}

static void test_no_edit_repack_trx_identical() {
    std::string td = fixture::mktemp_dir();
    TrxSandbox s = build_trx_gzip_sandbox(td);
    Recipe r = Recipe::from_extraction(s.image_path, s.ext, s.idj);
    std::string out = (std::filesystem::path(td) / "out.bin").string();
    RepackReport rep = Repacker(r).repack(out);
    CHECK(rep.identical, "no-edit trx repack identical");
    CHECK(fixture::slurp(out) == s.image, "no-edit trx output equals original");
    std::filesystem::remove_all(td);
}

static void test_end_to_end_fit_hash_fixed() {
    // A FIT embeds a gzip subimage that moria models as a region. Editing the
    // kernel re-encodes the gzip (padded to its slot), so the FIT payload
    // changes in place and its sha256 hash must be recomputed.
    std::string td = fixture::mktemp_dir();
    std::string kernel; for (int i = 0; i < 30; i++) kernel += "fit inner kernel, compressible ";
    std::string gz = gzip_compress(kernel, 9);
    BuiltFit bf = build_fit({{"kernel", gz, {{"sha256", fit_hash("sha256", gz)}}, false}});
    auto [doff, dlen] = bf.data_abs["kernel"];
    std::string image = bf.bytes;
    image.append(0x4000 - image.size(), (char)0xff);
    std::string image_path = (std::filesystem::path(td) / "firmware.bin").string();
    fixture::write_file(image_path, image);

    char sub[32]; std::snprintf(sub, sizeof(sub), "0x%llx-gzip", (unsigned long long)doff);
    std::string ext = image_path + ".extracted";
    fixture::write_file(ext + "/" + sub + "/decompressed", kernel);
    std::string manifest = std::string("{\"source\":\"") + image_path +
        "\",\"extracted\":[{\"offset\":" + std::to_string(doff) + ",\"type\":\"gzip\",\"root\":\"" +
        sub + "\",\"status\":\"ok\",\"depth\":1}]}";
    fixture::write_file(ext + "/manifest.json", manifest);
    std::string identify = std::string("{\"findings\":[{\"offset\":") + std::to_string(doff) +
        ",\"size\":" + std::to_string(dlen) + ",\"type\":\"gzip\",\"compression\":\"gzip\"}]}";
    std::string idj = (std::filesystem::path(td) / "identify.json").string();
    fixture::write_file(idj, identify);

    Recipe r = Recipe::from_extraction(image_path, ext, idj);
    fixture::write_file(ext + "/" + sub + "/decompressed", std::string(kernel.size(), '\0'));
    std::string out = (std::filesystem::path(td) / "out.bin").string();
    RepackReport rep = Repacker(r).repack(out);
    bool fit_fixed = false;
    for (const auto& f : rep.fixups) if (f.kind == "fit" && f.status == "fixed") fit_fixed = true;
    CHECK(fit_fixed, "end-to-end fit hash fixed reported");
    std::string blob = fixture::slurp(out);
    auto [voff, vlen] = bf.hash_abs["kernel|sha256"];
    CHECK(blob.substr(voff, vlen) == sha256_raw(blob.substr(doff, dlen)), "end-to-end fit sha256 valid");
    std::filesystem::remove_all(td);
}

int main() {
    test_trx_fixed_on_change();
    test_trx_noop();
    test_trx_not_fixed_if_invalid();
    test_uboot_env_fixed();
    test_uboot_env_redundant();
    test_seama_fixed();
    test_fit_hash_recomputed_sha256();
    test_fit_crc32_and_sha1();
    test_fit_multiple_algos();
    test_fit_unchanged_quiet();
    test_fit_signature_flagged();
    test_fit_not_recomputed_if_invalid();
    test_plain_dtb_not_flagged();
    test_nested_inner_then_outer();
    test_end_to_end_trx_fixed();
    test_end_to_end_fit_hash_fixed();
    test_no_edit_repack_trx_identical();
    if (failures) { std::cerr << failures << " fixups check(s) failed\n"; return 1; }
    std::cout << "all fixups tests passed\n";
    return 0;
}
