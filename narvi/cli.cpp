// cli.cpp -- narvi command-line interface.
//   narvi plan   IMAGE [--extracted DIR] [--identify JSON] [-o recipe.json]
//   narvi status RECIPE
//   narvi repack RECIPE [-o out.bin] [--policy fixed|reflow] [--pad 0xNN]
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#include "narvi/recipe.hpp"
#include "narvi/repacker.hpp"
#include "narvi/verify.hpp"
#include "narvi/fdt.hpp"
#include "narvi/proc.hpp"

using namespace narvi;

static std::string opt(const std::vector<std::string>& a, const std::string& flag,
                       const std::string& def = "") {
    for (size_t i = 0; i + 1 < a.size(); ++i)
        if (a[i] == flag) return a[i + 1];
    return def;
}

static bool has_flag(const std::vector<std::string>& a, const std::string& flag) {
    for (const auto& s : a) if (s == flag) return true;
    return false;
}

// First non-flag positional at or after index `from` (skips --opt VALUE pairs
// and bare --flags). Returns "" if none.
static std::string positional(const std::vector<std::string>& a, size_t from) {
    static const std::vector<std::string> valued = {"--extracted", "--identify", "-o",
                                                     "--policy", "--pad", "--recipe"};
    for (size_t i = from; i < a.size(); ++i) {
        if (a[i].rfind("--", 0) == 0 || a[i] == "-o") {
            bool takes_val = false;
            for (const auto& v : valued) if (a[i] == v) takes_val = true;
            if (takes_val) ++i;  // skip its value
            continue;
        }
        return a[i];
    }
    return "";
}

static int usage(bool to_stdout = false) {
    (to_stdout ? std::cout : std::cerr) <<
        "narvi -- repack firmware that moria extracted\n"
        "  narvi init FIRMWARE [-o recipe.json] [--moria PATH] [--force] [--no-verify]\n"
        "                                      extract + identify + plan in one step\n"
        "  narvi plan   IMAGE [--extracted DIR] [--identify JSON] [-o recipe.json]\n"
        "               [--no-verify] [--deep]\n"
        "  narvi status RECIPE\n"
        "  narvi repack RECIPE [-o out.bin] [--policy fixed|reflow] [--pad 0xNN] [--no-fixups]\n"
        "  narvi fdt FILE [--offset 0xN]      inspect an FDT/FIT: tree summary + round-trip\n"
        "  narvi verify ORIG REPACKED [--recipe recipe.json]\n"
        "  narvi check  RECIPE [--deep]\n";
    return 2;
}

int main(int argc, char** argv) {
    std::vector<std::string> a(argv + 1, argv + argc);
    if (a.empty()) return usage();
    std::string cmd = a[0];
    if (cmd == "--help" || cmd == "-h" || cmd == "help") { usage(/*to_stdout=*/true); return 0; }

    try {
        if (cmd == "init") {
            // One command: extract + identify + plan. Doing extract and plan
            // together captures the pristine baseline immediately, so there is no
            // window in which to edit before planning (edits go strictly after).
            if (a.size() < 2) return usage();
            std::string image = a[1];
            std::string moria = opt(a, "--moria", "moria");
            std::string out = opt(a, "-o", image + ".recipe.json");
            std::string extracted = opt(a, "--extracted", image + ".extracted");
            std::string idj = opt(a, "--identify", image + ".identify.json");
            if (!on_path(moria))
                throw std::runtime_error("'" + moria + "' not found on PATH -- install moria "
                                         "(github.com/nmatt0/moria) or pass --moria <path>");
            if (::access(extracted.c_str(), F_OK) == 0 && !has_flag(a, "--force"))
                throw std::runtime_error(
                    "'" + extracted + "' already exists -- refusing to re-extract over possible "
                    "edits. Edit files there and run `narvi repack`, or pass --force to start fresh.");
            std::cout << "[1/3] extracting   moria -e " << image << std::endl;
            if (run({moria, "-e", image}) != 0)
                throw std::runtime_error("moria extraction failed");
            std::cout << "[2/3] identifying  moria -j " << image << " > " << idj << std::endl;
            if (run({moria, "-j", image}, idj) != 0)
                throw std::runtime_error("moria identify failed");
            std::cout << "[3/3] planning" << std::endl;
            Recipe r = Recipe::from_extraction(image, extracted, idj);
            r.save(out);
            std::cout << "\nplanned " << r.regions().size() << " region(s), "
                      << (r.segments.size() - r.regions().size()) << " gap(s) over "
                      << r.filesize << " bytes\nrecipe: " << out << "\n";
            if (!has_flag(a, "--no-verify")) {
                bool deep = has_flag(a, "--deep");
                VerifyResult v = verify_recipe(r, deep);
                std::cout << v.report(&r, deep) << "\n";
                if (!v.roundtrip.identical) return 2;
            }
            std::cout << "\nNext: edit files under " << extracted << "/, then\n"
                      << "  narvi repack " << out << " -o <output.bin> --policy reflow\n";
            return 0;
        }
        if (cmd == "plan") {
            if (a.size() < 2) return usage();
            std::string image = a[1];
            Recipe r = Recipe::from_extraction(image, opt(a, "--extracted"), opt(a, "--identify"));
            std::string out = opt(a, "-o", image + ".recipe.json");
            r.save(out);
            std::cout << "planned " << r.regions().size() << " region(s), "
                      << (r.segments.size() - r.regions().size()) << " gap(s) over "
                      << r.filesize << " bytes\nrecipe: " << out << "\n";
            if (!has_flag(a, "--no-verify")) {
                bool deep = has_flag(a, "--deep");
                VerifyResult v = verify_recipe(r, deep);
                std::cout << v.report(&r, deep) << "\n";
                if (!v.roundtrip.identical) return 2;
            }
            return 0;
        }
        if (cmd == "verify") {
            std::string orig = positional(a, 1), repacked = positional(a, 2);
            if (orig.empty() || repacked.empty()) return usage();
            std::ifstream fa(orig, std::ios::binary), fb(repacked, std::ios::binary);
            std::string A((std::istreambuf_iterator<char>(fa)), std::istreambuf_iterator<char>());
            std::string B((std::istreambuf_iterator<char>(fb)), std::istreambuf_iterator<char>());
            auto ranges = diff_ranges(A, B);
            if (ranges.empty()) {
                std::cout << "identical: " << A.size() << " bytes, no differences\n";
                return 0;
            }
            std::string rpath = opt(a, "--recipe");
            std::vector<std::string> lines;
            if (!rpath.empty()) { Recipe rc = Recipe::load(rpath); lines = name_ranges(ranges, rc); }
            else for (const auto& r : ranges) lines.push_back(r.str());
            uint64_t total = 0;
            for (const auto& r : ranges) total += r.length;
            std::cout << ranges.size() << " differing range(s), " << total << " bytes changed:\n";
            for (const auto& l : lines) std::cout << "  " << l << "\n";
            return 1;
        }
        if (cmd == "check") {
            std::string rpath = positional(a, 1);
            if (rpath.empty()) return usage();
            Recipe r = Recipe::load(rpath);
            bool deep = has_flag(a, "--deep");
            VerifyResult v = verify_recipe(r, deep);
            std::cout << v.report(&r, deep) << "\n";
            return v.roundtrip.identical ? 0 : 2;
        }
        if (cmd == "status") {
            if (a.size() < 2) return usage();
            Repacker rp(Recipe::load(a[1]));
            for (const auto& r : rp.status()) {
                char line[128];
                std::string indent(2 * r.depth, ' ');
                std::snprintf(line, sizeof(line), "%s0x%08llx  %-12s %s",
                              indent.c_str(), (unsigned long long)r.offset, r.type.c_str(),
                              r.changed ? "CHANGED" : "unchanged");
                std::cout << line << "\n";
            }
            return 0;
        }
        if (cmd == "repack") {
            if (a.size() < 2) return usage();
            Recipe r = Recipe::load(a[1]);
            std::string pad = opt(a, "--pad");
            if (!pad.empty()) r.pad_byte = (uint8_t)std::strtoul(pad.c_str(), nullptr, 0);
            std::string out = opt(a, "-o", "repacked.bin");
            bool do_fixups = !has_flag(a, "--no-fixups");
            RepackReport rep = Repacker(std::move(r)).repack(out, opt(a, "--policy", "fixed"), do_fixups);
            std::cout << rep.summary() << "wrote " << out << "\n";
            return 0;
        }
        if (cmd == "fdt") {
            if (a.size() < 2) return usage();
            std::ifstream in(a[1], std::ios::binary);
            if (!in) { std::cerr << "cannot open " << a[1] << "\n"; return 1; }
            std::string blob((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            std::string offs = opt(a, "--offset");
            uint64_t off = offs.empty() ? 0 : std::strtoull(offs.c_str(), nullptr, 0);
            Fdt fdt = parse_dtb(blob, off);               // throws -> caught below
            std::string rt = fdt.to_bytes();
            uint32_t total = ((uint32_t)(uint8_t)blob[off+4]<<24)|((uint32_t)(uint8_t)blob[off+5]<<16)|
                             ((uint32_t)(uint8_t)blob[off+6]<<8)|(uint32_t)(uint8_t)blob[off+7];
            bool identical = rt == blob.substr(off, total);
            std::cout << "FDT @0x" << std::hex << off << std::dec << "  version=" << fdt.version
                      << "  size=" << total << "  round-trip="
                      << (identical ? "identical" : "DIFFERS") << "\n";
            Node* images = fdt.path("/images");
            if (images) {
                std::cout << "images: " << images->children.size() << "\n";
                for (auto& sub : images->children) {
                    const std::string* data = sub.get("data");
                    std::string algos; bool sig = false;
                    for (auto& c : sub.children) {
                        if (c.name.rfind("hash", 0) == 0 && c.get("algo")) {
                            std::string a2 = *c.get("algo"); size_t z = a2.find('\0'); if (z!=std::string::npos) a2.resize(z);
                            if (!algos.empty()) { algos += ","; }
                            algos += a2;
                        }
                        if (c.name.rfind("signature", 0) == 0) sig = true;
                    }
                    std::string comp = "none";
                    if (sub.get("compression")) { comp = *sub.get("compression"); size_t z=comp.find('\0'); if(z!=std::string::npos) comp.resize(z); }
                    std::cout << "  " << sub.name;
                    for (size_t i = sub.name.size(); i < 16; i++) std::cout << ' ';
                    std::cout << " data=" << (data ? std::to_string(data->size()) : std::string("external"))
                              << " comp=" << comp << " hash=" << (algos.empty() ? "-" : algos)
                              << (sig ? " +signature" : "") << "\n";
                }
            }
            return 0;
        }
        return usage();
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}
