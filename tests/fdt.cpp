// fdt.cpp -- tests for the FDT tree model + serializer + FIT rebuild: byte
// round-trip fidelity, node/property editing, and length-changing subimage
// rebuilds.
#include <iostream>
#include <string>
#include <zlib.h>

#include "narvi/fdt.hpp"
#include "tests/fitbuild.hpp"

using namespace narvi;
using namespace fitbuild;

static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { std::cerr << "FAIL: " << (msg) << "\n"; ++failures; } } while (0)

static std::string zcompress(const std::string& d) {
    uLongf bound = compressBound(d.size());
    std::string out(bound, '\0');
    compress2((Bytef*)out.data(), &bound, (const Bytef*)d.data(), d.size(), 9);
    out.resize(bound);
    return out;
}
static std::string be32s(uint32_t v) {
    std::string s(4,'\0'); for (int i=0;i<4;i++) s[i]=(char)(uint8_t)(v>>(8*(3-i))); return s;
}
static uint32_t rd_be32(const std::string& b, size_t o) {
    return ((uint32_t)(uint8_t)b[o]<<24)|((uint32_t)(uint8_t)b[o+1]<<16)|
           ((uint32_t)(uint8_t)b[o+2]<<8)|(uint32_t)(uint8_t)b[o+3];
}

static BuiltFit sample(bool sig) {
    std::string gz = zcompress(std::string(20, 'k') + "kernel");
    std::string rd; for (int i = 0; i < 8; i++) rd += "ramdisk raw payload ";
    return build_fit({
        {"kernel", gz, {{"sha256", fit_hash("sha256", gz)}, {"crc32", fit_hash("crc32", gz)}}, sig},
        {"ramdisk", rd, {{"sha1", fit_hash("sha1", rd)}}, false},
    });
}

static bool hashes_valid(const std::string& fit) {
    FitLayout lay = parse_fit(fit, 0);
    if (lay.hashes.empty()) return false;
    for (const auto& h : lay.hashes) {
        std::string data = fit.substr(h.payload_off, h.payload_len);
        if (fit_hash(h.algo, data) != fit.substr(h.value_off, h.value_len)) return false;
    }
    return true;
}

// -------- round-trip --------
static void test_roundtrip_identical() {
    for (bool sig : {false, true}) {
        std::string fit = sample(sig).bytes;
        CHECK(parse_dtb(fit, 0).to_bytes() == fit, sig ? "round-trip w/ sig" : "round-trip");
    }
}
static void test_roundtrip_stable() {
    std::string fit = sample(false).bytes;
    std::string once = parse_dtb(fit, 0).to_bytes();
    std::string twice = parse_dtb(once, 0).to_bytes();
    CHECK(once == twice && once == fit, "reparse stable");
}

// -------- tree access + edit --------
static void test_tree_access() {
    BuiltFit bf = sample(false);
    Fdt f = parse_dtb(bf.bytes, 0);
    Node* k = f.path("/images/kernel");
    CHECK(k && k->get("type") && *k->get("type") == std::string("kernel\0", 7), "kernel type");
    CHECK(f.path("/images/nope") == nullptr, "missing path null");
    CHECK(f.path("/images")->children.size() == 2, "two images");
}
static void test_edit_value_roundtrips() {
    Fdt f = parse_dtb(sample(false).bytes, 0);
    f.path("/images/kernel")->set("type", std::string("firmware\0", 9));
    std::string out = f.to_bytes();
    Fdt g = parse_dtb(out, 0);
    CHECK(g.path("/images/kernel")->get("type") && *g.path("/images/kernel")->get("type") == std::string("firmware\0", 9),
          "edited value present");
    CHECK(*g.path("/images/ramdisk")->get("type") == std::string("kernel\0", 7), "sibling intact");
}
static void test_add_new_property() {
    Fdt f = parse_dtb(sample(false).bytes, 0);
    f.root.set("description", std::string("narvi rebuilt\0", 14));
    std::string out = f.to_bytes();
    Fdt g = parse_dtb(out, 0);
    CHECK(g.root.get("description") && *g.root.get("description") == std::string("narvi rebuilt\0", 14),
          "new prop present");
    CHECK(g.path("/images/kernel") != nullptr, "tree intact after add");
}

// -------- rebuild_fit --------
static void test_rebuild_no_edits_identical() {
    std::string fit = sample(false).bytes;
    auto [out, rep] = rebuild_fit(fit, {});
    CHECK(out == fit, "rebuild no-edit byte-identical");
    CHECK(rep.resized.empty() && rep.invalidated_sigs.empty(), "rebuild no-edit quiet");
}
static void test_rebuild_grow() {
    std::string fit = sample(false).bytes;
    std::string bigger = zcompress(std::string(60 * 30, 'X'));
    auto [out, rep] = rebuild_fit(fit, {{"kernel", bigger}});
    CHECK(!rep.resized.empty() && std::get<0>(rep.resized[0]) == "kernel", "grow reported");
    CHECK(out.size() > fit.size(), "grow enlarges");
    CHECK(hashes_valid(out), "grow hashes valid");
    CHECK(*parse_dtb(out, 0).path("/images/kernel")->get("data") == bigger, "grow data replaced");
}
static void test_rebuild_shrink() {
    std::string fit = sample(false).bytes;
    std::string smaller = "tiny12";
    auto [out, rep] = rebuild_fit(fit, {{"kernel", smaller}});
    CHECK(out.size() < fit.size(), "shrink reduces");
    CHECK(hashes_valid(out), "shrink hashes valid");
    CHECK(*parse_dtb(out, 0).path("/images/kernel")->get("data") == smaller, "shrink data replaced");
}
static void test_rebuild_data_size() {
    Fdt f = parse_dtb(sample(false).bytes, 0);
    Node* k = f.path("/images/kernel");
    k->set("data-size", be32s((uint32_t)k->get("data")->size()));
    std::string fit2 = f.to_bytes();
    std::string nk = zcompress(std::string(40 * 15, 'Z'));
    auto [out, rep] = rebuild_fit(fit2, {{"kernel", nk}});
    Fdt g = parse_dtb(out, 0);
    CHECK(rd_be32(*g.path("/images/kernel")->get("data-size"), 0) == nk.size(), "data-size updated");
}
static void test_rebuild_multiple() {
    std::string fit = sample(false).bytes;
    std::string nk = zcompress(std::string(90, 'a')), nr = "r2r2r2r2r2r2";
    auto [out, rep] = rebuild_fit(fit, {{"kernel", nk}, {"ramdisk", nr}});
    CHECK(rep.resized.size() == 2, "two resized");
    CHECK(hashes_valid(out), "multi hashes valid");
    Fdt g = parse_dtb(out, 0);
    CHECK(*g.path("/images/kernel")->get("data") == nk && *g.path("/images/ramdisk")->get("data") == nr,
          "multi data replaced");
}
static void test_rebuild_signature_flagged() {
    std::string fit = sample(true).bytes;
    auto [out, rep] = rebuild_fit(fit, {{"kernel", zcompress(std::string(30, 'c'))}});
    bool flagged = false; for (auto& s : rep.invalidated_sigs) if (s == "kernel") flagged = true;
    CHECK(flagged, "signature flagged");
    CHECK(hashes_valid(out), "sig-case hashes valid");
}
static void test_rebuild_external_skipped() {
    Fdt f = parse_dtb(sample(false).bytes, 0);
    Node* k = f.path("/images/kernel");
    std::vector<Prop> kept;
    for (auto& p : k->props) if (p.name != "data") kept.push_back(p);
    k->props = kept;
    k->set("data-size", be32s(24));
    k->set("data-offset", be32s(0));
    std::string ext = f.to_bytes();
    auto [out, rep] = rebuild_fit(ext, {{"kernel", std::string("whatever")}});
    bool skipped = false; for (auto& s : rep.external_skipped) if (s == "kernel") skipped = true;
    CHECK(skipped, "external data skipped");
}

int main() {
    test_roundtrip_identical();
    test_roundtrip_stable();
    test_tree_access();
    test_edit_value_roundtrips();
    test_add_new_property();
    test_rebuild_no_edits_identical();
    test_rebuild_grow();
    test_rebuild_shrink();
    test_rebuild_data_size();
    test_rebuild_multiple();
    test_rebuild_signature_flagged();
    test_rebuild_external_skipped();
    if (failures) { std::cerr << failures << " fdt check(s) failed\n"; return 1; }
    std::cout << "all fdt tests passed\n";
    return 0;
}
