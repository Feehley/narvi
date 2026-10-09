// fitrebuild.cpp -- end-to-end tests for the FIT (.itb) rebuilder in `repack`:
// grow/shrink a subimage, re-compress only the changed one, recompute hashes,
// flag signatures, and rebuild through a nested container.
#include <filesystem>
#include <iostream>
#include <map>
#include <string>

#include "narvi/fdt.hpp"
#include "narvi/recipe.hpp"
#include "narvi/repacker.hpp"
#include "narvi/rebuilders.hpp"
#include "tests/fixture.hpp"
#include "tests/fitbuild.hpp"

using namespace narvi;
namespace fs = std::filesystem;

static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { std::cerr << "FAIL: " << (msg) << "\n"; ++failures; } } while (0)

static std::string gz(const std::string& d) { return gzip_compress(d, 9); }
static std::string rep_str(const std::string& s, int n) { std::string o; for (int i=0;i<n;i++) o+=s; return o; }

struct Sandbox { std::string image_path, ext, idj, fit; };

// images: (name, decompressed, comp, [algos], sig)
struct Img { std::string name, raw, comp; std::vector<std::string> algos; bool sig; };

static Sandbox sandbox(const std::string& td, const std::vector<Img>& images, size_t pad_to = 0x8000) {
    std::vector<fitbuild::FitImage> built;
    std::map<std::string, std::string> raw_by_name;
    for (auto& im : images) {
        std::string stored = (im.comp == "gzip") ? gz(im.raw)
                           : (im.comp == "lzma") ? lzma_alone_compress(im.raw, 6)
                           : im.raw;
        raw_by_name[im.name] = im.raw;
        std::vector<std::pair<std::string,std::string>> hs;
        for (auto& a : im.algos) hs.push_back({a, fitbuild::fit_hash(a, stored)});
        built.push_back({im.name, stored, hs, im.sig});
    }
    // build_fit hardcodes compression="none"; patch each subimage's compression via the tree.
    auto bf = fitbuild::build_fit(built);
    Fdt fdt = parse_dtb(bf.bytes, 0);
    for (auto& im : images) {
        Node* sub = fdt.path("/images/" + im.name);
        sub->set("compression", im.comp + std::string(1, '\0'));
    }
    std::string fit = fdt.to_bytes();

    std::string image = fit + std::string(pad_to - fit.size(), (char)0xff);
    Sandbox s;
    s.image_path = (fs::path(td) / "firmware.bin").string();
    fixture::write_file(s.image_path, image);
    s.ext = s.image_path + ".extracted";
    for (auto& im : images)
        fixture::write_file(s.ext + "/0x0-fit/" + im.name, raw_by_name[im.name]);
    std::string manifest = std::string("{\"source\":\"") + s.image_path +
        "\",\"extracted\":[{\"offset\":0,\"type\":\"fit\",\"root\":\"0x0-fit\",\"status\":\"ok\",\"depth\":1}]}";
    fixture::write_file(s.ext + "/manifest.json", manifest);
    s.idj = (fs::path(td) / "identify.json").string();
    fixture::write_file(s.idj, std::string("{\"findings\":[{\"offset\":0,\"size\":") +
                        std::to_string(fit.size()) + ",\"type\":\"fit\"}]}");
    s.fit = fit;
    return s;
}

static bool hashes_valid(const std::string& blob) {
    FitLayout lay = parse_fit(blob, 0);
    if (lay.hashes.empty()) return false;
    for (auto& h : lay.hashes)
        if (fitbuild::fit_hash(h.algo, blob.substr(h.payload_off, h.payload_len)) !=
            blob.substr(h.value_off, h.value_len)) return false;
    return true;
}

static void test_grow_reflow() {
    std::string td = fixture::mktemp_dir();
    Sandbox s = sandbox(td, {{"kernel", rep_str("small kernel ", 4), "gzip", {"sha256","crc32"}, false}});
    Recipe r = Recipe::from_extraction(s.image_path, s.ext, s.idj);
    std::string bigger = rep_str("MUCH bigger kernel payload now ", 40);
    fixture::write_file(s.ext + "/0x0-fit/kernel", bigger);
    std::string out = (fs::path(td) / "out.bin").string();
    Repacker(std::move(r)).repack(out, "reflow");
    std::string blob = fixture::slurp(out);
    CHECK(hashes_valid(blob), "grow: hashes valid");
    Fdt g = parse_dtb(blob, 0);
    Node* k = g.path("/images/kernel");
    CHECK(gzip_decompress(*k->get("data")) == bigger, "grow: kernel re-gzipped");
}

static void test_shrink_fixed() {
    std::string td = fixture::mktemp_dir();
    Sandbox s = sandbox(td, {{"kernel", rep_str("a fairly chunky kernel payload here ", 20), "gzip", {"sha256"}, false}});
    Recipe r = Recipe::from_extraction(s.image_path, s.ext, s.idj);
    fixture::write_file(s.ext + "/0x0-fit/kernel", "tiny");
    std::string out = (fs::path(td) / "out.bin").string();
    Repacker(std::move(r)).repack(out, "fixed");
    std::string blob = fixture::slurp(out);
    CHECK(blob.size() == 0x8000, "shrink fixed: image size preserved");
    CHECK(hashes_valid(blob), "shrink: hashes valid");
    CHECK(gzip_decompress(*parse_dtb(blob, 0).path("/images/kernel")->get("data")) == "tiny", "shrink: data");
}

static void test_no_edit_identical() {
    std::string td = fixture::mktemp_dir();
    Sandbox s = sandbox(td, {{"kernel", rep_str("unchanged kernel ", 8), "gzip", {"sha256"}, false}});
    Recipe r = Recipe::from_extraction(s.image_path, s.ext, s.idj);
    std::string out = (fs::path(td) / "out.bin").string();
    RepackReport rep = Repacker(std::move(r)).repack(out);
    CHECK(rep.identical, "no-edit FIT repack identical");
    CHECK(fixture::slurp(out) == fixture::slurp(s.image_path), "no-edit bytes equal");
}

static void test_multiple_subimages() {
    std::string td = fixture::mktemp_dir();
    Sandbox s = sandbox(td, {{"kernel", rep_str("kernel v1 ", 10), "gzip", {"sha256"}, false},
                             {"ramdisk", rep_str("ramdisk v1 ", 10), "none", {"crc32"}, false}});
    Recipe r = Recipe::from_extraction(s.image_path, s.ext, s.idj);
    fixture::write_file(s.ext + "/0x0-fit/kernel", rep_str("kernel V2 grown ", 20));
    fixture::write_file(s.ext + "/0x0-fit/ramdisk", rep_str("ramdisk V2 ", 30));
    std::string out = (fs::path(td) / "out.bin").string();
    Repacker(std::move(r)).repack(out, "reflow");
    std::string blob = fixture::slurp(out);
    CHECK(hashes_valid(blob), "multi: hashes valid");
    Fdt g = parse_dtb(blob, 0);
    CHECK(gzip_decompress(*g.path("/images/kernel")->get("data")) == rep_str("kernel V2 grown ", 20), "multi: kernel");
    CHECK(*g.path("/images/ramdisk")->get("data") == rep_str("ramdisk V2 ", 30), "multi: ramdisk raw");
}

static void test_signature_fixed_flagged() {
    std::string td = fixture::mktemp_dir();
    Sandbox s = sandbox(td, {{"kernel", rep_str("signed kernel payload ", 20), "gzip", {"sha256"}, true}});
    Recipe r = Recipe::from_extraction(s.image_path, s.ext, s.idj);
    fixture::write_file(s.ext + "/0x0-fit/kernel", "shrunk");
    std::string out = (fs::path(td) / "out.bin").string();
    RepackReport rep = Repacker(std::move(r)).repack(out, "fixed");
    bool flagged = false;
    for (auto& f : rep.fixups) if (f.kind == "fit" && f.status == "signature-invalidated") flagged = true;
    CHECK(flagged, "signature flagged under fixed policy");
}

static void test_nested_inside_subimage() {
    std::string td = fixture::mktemp_dir();
    std::string inner = rep_str("inner vmlinux bytes ", 20);
    std::string gzs = gz(inner);
    Sandbox s = sandbox(td, {{"kernel", gzs, "none", {"sha256"}, false}});
    // model the gzip nested inside the (comp=none) kernel subimage file
    std::string sub = "0x0-fit";
    fixture::write_file(s.ext + "/" + sub + "/kernel.extracted/0x0-gzip/decompressed", inner);
    std::string manifest = std::string("{\"source\":\"") + s.image_path +
        "\",\"extracted\":[{\"offset\":0,\"type\":\"fit\",\"root\":\"0x0-fit\",\"status\":\"ok\",\"depth\":1},"
        "{\"offset\":0,\"type\":\"gzip\",\"root\":\"0x0-fit/kernel.extracted/0x0-gzip\",\"status\":\"ok\",\"depth\":2}]}";
    fixture::write_file(s.ext + "/manifest.json", manifest);

    Recipe r = Recipe::from_extraction(s.image_path, s.ext, s.idj);
    std::string patched = rep_str("patched vmlinux bytes, longer than before ", 20);
    fixture::write_file(s.ext + "/" + sub + "/kernel.extracted/0x0-gzip/decompressed", patched);
    std::string out = (fs::path(td) / "out.bin").string();
    Repacker(std::move(r)).repack(out, "reflow");
    std::string blob = fixture::slurp(out);
    CHECK(hashes_valid(blob), "nested: hashes valid");
    CHECK(gzip_decompress(*parse_dtb(blob, 0).path("/images/kernel")->get("data")) == patched, "nested: inner patched");
}

static void test_lzma_subimage_rebuild() {
    std::string td = fixture::mktemp_dir();
    Sandbox s = sandbox(td, {{"kernel", rep_str("lzma vmlinux payload ", 12), "lzma", {"sha256","crc32"}, false}});
    Recipe r = Recipe::from_extraction(s.image_path, s.ext, s.idj);
    std::string bigger = rep_str("much larger lzma vmlinux payload after editing ", 30);
    fixture::write_file(s.ext + "/0x0-fit/kernel", bigger);
    std::string out = (fs::path(td) / "out.bin").string();
    Repacker(std::move(r)).repack(out, "reflow");
    std::string blob = fixture::slurp(out);
    CHECK(hashes_valid(blob), "lzma: hashes valid");
    Fdt g = parse_dtb(blob, 0);
    Node* k = g.path("/images/kernel");
    CHECK(lzma_alone_decompress(*k->get("data")) == bigger, "lzma: kernel re-compressed");
}

static void test_unsupported_codec_refused() {
    std::string td = fixture::mktemp_dir();
    // lz4 is not handled by the rebuilder; the refusal fires on the compression
    // property (sandbox stores raw bytes for an unknown codec, which is fine here).
    Sandbox s = sandbox(td, {{"kernel", rep_str("payload ", 10), "lz4", {"sha256"}, false}});
    Recipe r = Recipe::from_extraction(s.image_path, s.ext, s.idj);
    fixture::write_file(s.ext + "/0x0-fit/kernel", "edited");
    std::string out = (fs::path(td) / "out.bin").string();
    bool threw = false;
    try { Repacker(std::move(r)).repack(out, "reflow"); }
    catch (const std::exception& e) {
        threw = true;
        std::string m = e.what();
        CHECK(m.find("lz4") != std::string::npos && m.find("rebuild_fit") != std::string::npos,
              "refusal names codec + rebuild_fit");
    }
    CHECK(threw, "lz4 subimage edit refused");
}

int main() {
    test_grow_reflow();
    test_shrink_fixed();
    test_no_edit_identical();
    test_multiple_subimages();
    test_signature_fixed_flagged();
    test_nested_inside_subimage();
    test_lzma_subimage_rebuild();
    test_unsupported_codec_refused();
    if (failures) { std::cerr << failures << " fit-rebuild check(s) failed\n"; return 1; }
    std::cout << "all fit-rebuild tests passed\n";
    return 0;
}
