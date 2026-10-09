// nested.cpp -- recursive repack tests.
//
// Fixture (shared, see fixture.hpp): a uImage whose payload is a gzip stream (a
// depth-2 child), so an edit to the innermost decompressed content must
// propagate outward through the gzip and then the uImage header (ih_size + data
// CRC + header CRC). A sibling top-level gzip proves untouched containers stay
// byte-identical.
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <map>
#include <string>

#include <zlib.h>

#include "narvi/model.hpp"
#include "narvi/rebuilders.hpp"
#include "narvi/recipe.hpp"
#include "narvi/repacker.hpp"
#include "tests/fixture.hpp"

using namespace narvi;
using fixture::build_sandbox;
using fixture::gunzip;
using fixture::Meta;
using fixture::mktemp_dir;
using fixture::rd_be32;
using fixture::slurp;
using fixture::write_file;

static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { std::cerr << "FAIL: " << msg << "\n"; ++failures; } } while (0)

static void test_tree_is_reconstructed() {
    std::string td = mktemp_dir();
    Meta m = build_sandbox(td);
    Recipe r = Recipe::from_extraction(m.image_path, m.ext, m.idj);
    auto top = r.regions();
    CHECK(top.size() == 2, "two top-level regions");
    CHECK(top[0].type == "uimage" && top[1].type == "gzip", "top types uimage,gzip");
    CHECK(top[0].children.size() == 1, "uimage has one child");
    const Segment& child = top[0].children[0];
    CHECK(child.type == "gzip" && child.depth == 2, "child is depth-2 gzip");
    CHECK(child.parent_file == "payload", "child lives in payload");
    CHECK(child.offset == 0 && child.length == m.gz.size(), "child span == gzip stream");
    std::filesystem::remove_all(td);
}

static void test_nested_unchanged_is_byte_identical() {
    std::string td = mktemp_dir();
    Meta m = build_sandbox(td);
    Recipe r = Recipe::from_extraction(m.image_path, m.ext, m.idj);
    std::string out = (std::filesystem::path(td) / "out.bin").string();
    RepackReport rep = Repacker(r).repack(out);
    CHECK(rep.identical, "unchanged nested repack is identical");
    CHECK(slurp(out) == m.image, "unchanged output equals original bytes");
    std::filesystem::remove_all(td);
}

static void test_nested_save_load_identical() {
    std::string td = mktemp_dir();
    Meta m = build_sandbox(td);
    Recipe r = Recipe::from_extraction(m.image_path, m.ext, m.idj);
    std::string rp = (std::filesystem::path(td) / "r.json").string();
    r.save(rp);
    Recipe r2 = Recipe::load(rp);
    CHECK(r2.regions()[0].children.size() == 1, "tree survives save/load");
    std::string out = (std::filesystem::path(td) / "out.bin").string();
    CHECK(Repacker(r2).repack(out).identical, "reloaded recipe repacks identical");
    std::filesystem::remove_all(td);
}

static void test_edit_innermost_propagates_outward() {
    std::string td = mktemp_dir();
    Meta m = build_sandbox(td);
    Recipe r = Recipe::from_extraction(m.image_path, m.ext, m.idj);

    std::string new_kernel(m.kernel.size(), '\0');      // compresses smaller -> fits slot
    write_file(m.ext + "/0x0-uimage/payload.extracted/0x0-gzip/decompressed", new_kernel);

    Repacker rp(r);
    std::map<std::pair<std::string, int>, bool> st;
    for (const auto& rr : rp.status()) st[std::make_pair(rr.type, rr.depth)] = rr.changed;
    bool uimg_dirty = st[std::make_pair(std::string("uimage"), 1)];
    bool nested_dirty = st[std::make_pair(std::string("gzip"), 2)];
    bool sibling_dirty = st[std::make_pair(std::string("gzip"), 1)];
    CHECK(uimg_dirty, "parent uimage dirty via child");
    CHECK(nested_dirty, "nested gzip dirty");
    CHECK(!sibling_dirty, "sibling gzip untouched");

    std::string out = (std::filesystem::path(td) / "out.bin").string();
    RepackReport rep = rp.repack(out);
    CHECK(!rep.identical, "edited nested repack differs");
    std::string blob = slurp(out);
    CHECK(blob.size() == m.image.size(), "fixed layout preserves size");

    CHECK(rd_be32(blob, 0) == UIMAGE_MAGIC, "uimage magic present");
    std::string new_gz = gzip_compress(new_kernel, 9);
    uint32_t ih_size = rd_be32(blob, 12);
    CHECK(ih_size == new_gz.size(), "ih_size reflects recompressed child");
    CHECK(rd_be32(blob, 24) == crc32_of(new_gz), "ih_dcrc updated");
    std::string hdr = blob.substr(0, UIMAGE_HDR);
    uint32_t stored_hcrc = rd_be32(hdr, 4);
    for (int i = 4; i < 8; i++) hdr[i] = 0;
    CHECK(crc32_of(hdr) == stored_hcrc, "ih_hcrc updated");

    std::string payload = blob.substr(UIMAGE_HDR, ih_size);
    CHECK(gunzip(payload) == new_kernel, "payload inflates to edited kernel");

    CHECK(blob.substr(m.b_off, m.b_len) == m.gz2, "sibling region verbatim");
    std::filesystem::remove_all(td);
}

static void test_edit_sibling_leaves_container_verbatim() {
    std::string td = mktemp_dir();
    Meta m = build_sandbox(td);
    Recipe r = Recipe::from_extraction(m.image_path, m.ext, m.idj);
    write_file(m.ext + "/0x2000-gzip/decompressed", std::string(m.other.size(), '\0'));
    std::string out = (std::filesystem::path(td) / "out.bin").string();
    RepackReport rep = Repacker(r).repack(out);
    std::string blob = slurp(out);
    CHECK(blob.substr(0, m.slot) == m.image.substr(0, m.slot), "uimage container + slot untouched");
    bool sib = false;
    for (const auto& rr : rep.regions)
        if (rr.changed && rr.type == "gzip" && rr.depth == 1) sib = true;
    CHECK(sib, "sibling gzip reported changed");
    std::filesystem::remove_all(td);
}

int main() {
    test_tree_is_reconstructed();
    test_nested_unchanged_is_byte_identical();
    test_nested_save_load_identical();
    test_edit_innermost_propagates_outward();
    test_edit_sibling_leaves_container_verbatim();
    if (failures) { std::cerr << failures << " nested check(s) failed\n"; return 1; }
    std::cout << "all nested tests passed\n";
    return 0;
}
