// cpio.cpp -- tests for the cpio (newc 070701 / crc 070702) rebuilder, end to
// end through Recipe/Repacker: a no-edit repack is byte-identical, and editing a
// member rebuilds the archive with the member's c_filesize (and, for 070702, the
// c_check data checksum at header offset 102) corrected while every other member
// and the trailer stay intact.
#include <filesystem>
#include <iostream>
#include <string>

#include "narvi/recipe.hpp"
#include "narvi/repacker.hpp"
#include "tests/fixture.hpp"

namespace fs = std::filesystem;
static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { std::cerr << "FAIL: " << (msg) << "\n"; ++failures; } } while (0)

static uint64_t align4(uint64_t x) { return (x + 3) & ~uint64_t(3); }

struct Member { std::string name; uint32_t mode; std::string data; };

// Build a newc/crc archive. c_check (offset 102) is the byte sum for 070702,
// else 0. Returns the archive bytes.
static std::string build_cpio(const std::string& magic, const std::vector<Member>& ms) {
    bool crc = (magic == "070702");
    std::string out;
    uint32_t ino = 1;
    auto emit = [&](const std::string& name, uint32_t mode, const std::string& data) {
        uint32_t chk = 0;
        if (crc) for (unsigned char c : data) chk += c;
        std::string nb = name; nb.push_back('\0');
        uint32_t fields[13] = { ino++, mode, 0, 0, 1, 0, (uint32_t)data.size(),
                                1, 0, 0, 0, (uint32_t)nb.size(), chk };
        char hdr[111];
        std::snprintf(hdr, sizeof(hdr), "%s%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
                      magic.c_str(), fields[0], fields[1], fields[2], fields[3], fields[4],
                      fields[5], fields[6], fields[7], fields[8], fields[9], fields[10],
                      fields[11], fields[12]);
        std::string blob(hdr, 110);
        blob += nb;
        blob.append((size_t)align4(blob.size()) - blob.size(), '\0');
        blob += data;
        blob.append((size_t)align4(data.size()) - data.size(), '\0');
        out += blob;
    };
    for (auto& m : ms) emit(m.name, m.mode, m.data);
    emit("TRAILER!!!", 0, "");
    out.append((size_t)align4(out.size()) - out.size(), '\0');
    return out;
}

// Lay the archive down as a moria "cpio" region extraction at offset 0.
static void sandbox(const std::string& td, const std::string& magic,
                    const std::vector<Member>& ms, std::string& image_path,
                    std::string& ext, std::string& idj, std::string& archive) {
    archive = build_cpio(magic, ms);
    std::string image = std::string(64, '\0') + archive + std::string(32, '\xff');
    // moria would find the cpio at offset 64; keep it simple and place it at 0.
    image = archive + std::string(64, '\xff');
    image_path = (fs::path(td) / "fw.bin").string();
    fixture::write_file(image_path, image);
    ext = image_path + ".extracted";
    for (auto& m : ms) {
        std::string p = ext + "/0x0-cpio/" + m.name;
        if ((m.mode & 0170000) == 0040000) { std::error_code ec; fs::create_directories(p, ec); }
        else if ((m.mode & 0170000) == 0120000) { std::error_code ec;
            fs::create_directories(fs::path(p).parent_path(), ec); fs::create_symlink(m.data, p, ec); }
        else fixture::write_file(p, m.data);
    }
    fixture::write_file(ext + "/manifest.json",
        std::string("{\"source\":\"") + image_path +
        "\",\"extracted\":[{\"offset\":0,\"type\":\"cpio\",\"root\":\"0x0-cpio\",\"status\":\"ok\",\"depth\":1}]}");
    idj = (fs::path(td) / "id.json").string();
    fixture::write_file(idj, std::string("{\"findings\":[{\"offset\":0,\"size\":") +
                        std::to_string(archive.size()) + ",\"type\":\"cpio\"}]}");
}

static std::vector<Member> sample() {
    return {
        {".",            0040755, ""},
        {"etc",          0040755, ""},
        {"etc/motd",     0100644, "hello initramfs\n"},
        {"init",         0100755, "#!/bin/sh\necho init\n"},
        {"bin",          0040755, ""},
        {"bin/busybox",  0100755, std::string("ELF-ish busybox blob ") + "ELF-ish busybox blob "},
        {"bin/sh",       0120777, "busybox"},   // symlink target
    };
}

// pull one member's (filesize, check, data) out of a rebuilt archive at off
static std::tuple<uint64_t,uint64_t,std::string> member(const std::string& buf, size_t off,
                                                        const std::string& want) {
    size_t pos = off, n = buf.size();
    auto g = [&](size_t o){ return std::stoul(buf.substr(pos + o, 8), nullptr, 16); };
    while (pos + 110 <= n) {
        std::string magic = buf.substr(pos, 6);
        if (magic != "070701" && magic != "070702") break;
        uint64_t fsz = g(54), nsz = g(94), chk = g(102);
        std::string name = buf.substr(pos + 110, nsz);
        if (auto z = name.find('\0'); z != std::string::npos) name.resize(z);
        size_t data_off = pos + (size_t)align4(110 + nsz);
        if (name == "TRAILER!!!") break;
        if (name == want) return {fsz, chk, buf.substr(data_off, (size_t)fsz)};
        pos = data_off + (size_t)align4(fsz);
    }
    return {0, 0, std::string("<not found>")};
}

static void run(const std::string& magic) {
    std::string td = fixture::mktemp_dir();
    std::string img, ext, idj, archive;
    sandbox(td, magic, sample(), img, ext, idj, archive);

    narvi::Recipe r = narvi::Recipe::from_extraction(img, ext, idj);

    // 1) no-edit repack is byte-identical
    std::string out1 = (fs::path(td) / "rt.bin").string();
    narvi::Repacker(r).repack(out1, "fixed");
    CHECK(fixture::slurp(out1) == fixture::slurp(img), magic + ": no-edit repack byte-identical");

    // 2) edit a member -> rebuilt archive carries the new bytes + corrected header.
    // Reuse the recipe planned above (its baseline is the pristine tree); editing
    // then re-planning would recapture the edit as the baseline.
    std::string want = "patched motd of a different length than the original\n";
    fixture::write_file(ext + "/0x0-cpio/etc/motd", want);
    std::string out2 = (fs::path(td) / "ed.bin").string();
    narvi::Repacker(r).repack(out2, "reflow");
    std::string ed = fixture::slurp(out2);

    auto [fsz, chk, data] = member(ed, 0, "etc/motd");
    CHECK(data == want && fsz == want.size(), magic + ": motd rebuilt with new bytes + size");
    uint32_t expect = 0; if (magic == "070702") for (unsigned char c : want) expect += c;
    CHECK(chk == expect, magic + ": motd c_check correct");

    // unchanged members survive intact (proves no desync past the edit)
    auto [bfsz, bchk, bdata] = member(ed, 0, "bin/busybox");
    uint32_t bexpect = 0; if (magic == "070702") for (unsigned char c : bdata) bexpect += c;
    CHECK(bdata == std::string("ELF-ish busybox blob ") + "ELF-ish busybox blob ",
          magic + ": busybox intact after upstream edit");
    CHECK(bchk == bexpect, magic + ": busybox c_check preserved");
    auto [sfsz, schk, sdata] = member(ed, 0, "bin/sh");
    CHECK(sdata == "busybox", magic + ": symlink target intact");
    (void)bfsz; (void)sfsz; (void)schk;
}

int main() {
    run("070701");
    run("070702");
    if (failures) { std::cerr << failures << " cpio check(s) failed\n"; return 1; }
    std::cout << "all cpio tests passed\n";
    return 0;
}
