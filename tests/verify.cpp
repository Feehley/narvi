// verify.cpp -- tests for the provenance layer: byte-range diff, the plan-time
// round-trip guard, and per-region re-encode fidelity.
#include <cstdint>
#include <iostream>
#include <map>
#include <string>

#include "narvi/recipe.hpp"
#include "narvi/repacker.hpp"
#include "narvi/verify.hpp"
#include "tests/fixture.hpp"

using namespace narvi;
using fixture::build_sandbox;
using fixture::Meta;
using fixture::mktemp_dir;
using fixture::write_file;

static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { std::cerr << "FAIL: " << msg << "\n"; ++failures; } } while (0)

static std::vector<std::pair<uint64_t, uint64_t>> pairs(const std::vector<ByteRange>& r) {
    std::vector<std::pair<uint64_t, uint64_t>> out;
    for (const auto& x : r) out.push_back({x.offset, x.length});
    return out;
}

// Mutate the first top-level region of a given type in the recipe's own segments.
static Segment* find_top(Recipe& r, const std::string& type) {
    for (auto& s : r.segments)
        if (s.is_region() && s.depth == 1 && s.type == type) return &s;
    return nullptr;
}

// ---------------------------------------------------------------- diff_ranges
static void test_diff_ranges_basic() {
    auto r = diff_ranges("AAAABBBBCCCC", "AAAAXBBBCYCC");
    auto p = pairs(r);
    CHECK((p == std::vector<std::pair<uint64_t, uint64_t>>{{4, 1}, {9, 1}}), "diff basic");
}
static void test_diff_ranges_identical() {
    CHECK(diff_ranges("hello", "hello").empty(), "diff identical empty");
}
static void test_diff_ranges_length_tail() {
    auto p = pairs(diff_ranges("same", "sameEXTRA"));
    CHECK((p == std::vector<std::pair<uint64_t, uint64_t>>{{4, 5}}), "diff length tail");
}
static void test_diff_ranges_merge_boundary() {
    auto p = pairs(diff_ranges("abcd", "abXYZW"));
    CHECK((p == std::vector<std::pair<uint64_t, uint64_t>>{{2, 4}}), "diff merge boundary");
}

// ------------------------------------------------------------ round-trip guard
static void test_roundtrip_ok() {
    std::string td = mktemp_dir();
    Meta m = build_sandbox(td);
    Recipe r = Recipe::from_extraction(m.image_path, m.ext, m.idj);
    RoundTripResult res = roundtrip_check(r);
    CHECK(res.identical, "fresh recipe round-trips");
    CHECK(res.ranges.empty(), "no differing ranges");
    CHECK(res.report(&r).find("round-trip OK") != std::string::npos, "report says OK");
    std::filesystem::remove_all(td);
}

static void test_roundtrip_detects_corruption() {
    std::string td = mktemp_dir();
    Meta m = build_sandbox(td);
    Recipe r = Recipe::from_extraction(m.image_path, m.ext, m.idj);
    Segment* sib = find_top(r, "gzip");
    CHECK(sib != nullptr, "found sibling gzip");
    if (sib) {
        sib->content_sha256 = "deadbeef";   // now looks edited
        sib->length = sib->length - 1;       // and no longer fits its slot -> repack fails
    }
    RoundTripResult res = roundtrip_check(r);
    CHECK(!res.identical, "corruption is caught (non-identical or error)");
    std::filesystem::remove_all(td);
}

static void test_verify_report_deep_mentions_fidelity() {
    std::string td = mktemp_dir();
    Meta m = build_sandbox(td);
    Recipe r = Recipe::from_extraction(m.image_path, m.ext, m.idj);
    VerifyResult v = verify_recipe(r, /*deep=*/true);
    std::string text = v.report(&r, true);
    CHECK(text.find("round-trip OK") != std::string::npos, "deep report has round-trip");
    CHECK(text.find("re-encode fidelity") != std::string::npos, "deep report has fidelity");
    std::filesystem::remove_all(td);
}

// ------------------------------------------------------------- fidelity probe
static void test_fidelity_exact() {
    std::string td = mktemp_dir();
    Meta m = build_sandbox(td);
    Recipe r = Recipe::from_extraction(m.image_path, m.ext, m.idj);
    std::map<std::pair<std::string, int>, std::string> st;
    for (const auto& f : reencode_fidelity(r)) st[{f.type, f.depth}] = f.status;
    CHECK(st[std::make_pair(std::string("uimage"), 1)] == "exact", "uimage exact");
    CHECK(st[std::make_pair(std::string("gzip"), 2)] == "exact", "nested gzip exact");
    CHECK(st[std::make_pair(std::string("gzip"), 1)] == "exact", "sibling gzip exact");
    std::filesystem::remove_all(td);
}

static void test_fidelity_no_encoder() {
    std::string td = mktemp_dir();
    Meta m = build_sandbox(td);
    Recipe r = Recipe::from_extraction(m.image_path, m.ext, m.idj);
    Segment* sib = find_top(r, "gzip");
    if (sib) sib->type = "jffs2";                 // a type with no rebuilder
    std::map<std::pair<std::string, int>, std::string> st;
    for (const auto& f : reencode_fidelity(r)) st[{f.type, f.depth}] = f.status;
    CHECK(st[std::make_pair(std::string("jffs2"), 1)] == "no-encoder", "unsupported -> no-encoder");
    std::filesystem::remove_all(td);
}

int main() {
    test_diff_ranges_basic();
    test_diff_ranges_identical();
    test_diff_ranges_length_tail();
    test_diff_ranges_merge_boundary();
    test_roundtrip_ok();
    test_roundtrip_detects_corruption();
    test_verify_report_deep_mentions_fidelity();
    test_fidelity_exact();
    test_fidelity_no_encoder();
    if (failures) { std::cerr << failures << " verify check(s) failed\n"; return 1; }
    std::cout << "all verify tests passed\n";
    return 0;
}
