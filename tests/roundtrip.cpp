// roundtrip.cpp -- end-to-end tests against moria-shaped fixtures.
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#include <zlib.h>

#include "narvi/codecs.hpp"
#include "narvi/rebuilders.hpp"
#include "narvi/recipe.hpp"
#include "narvi/repacker.hpp"
#include "narvi/sha256.hpp"

namespace fs = std::filesystem;
using namespace narvi;

static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { std::cerr << "FAIL: " << msg << "\n"; ++failures; } } while (0)

static void write_file(const std::string& p, const std::string& data) {
    fs::create_directories(fs::path(p).parent_path());
    std::ofstream f(p, std::ios::binary);
    f.write(data.data(), (std::streamsize)data.size());
}

static std::string be32(uint32_t v) {
    std::string s(4, '\0');
    s[0]=(char)(v>>24); s[1]=(char)(v>>16); s[2]=(char)(v>>8); s[3]=(char)v;
    return s;
}

static std::string make_uimage(const std::string& payload) {
    std::string h(UIMAGE_HDR, '\0');
    auto put = [&](size_t off, const std::string& v){ for (size_t i=0;i<4;i++) h[off+i]=v[i]; };
    put(0, be32(UIMAGE_MAGIC));
    put(8, be32(0));                         // time
    put(12, be32((uint32_t)payload.size())); // size
    put(24, be32(crc32_of(payload)));        // dcrc
    h[28]=5; h[29]=2; h[30]=2; h[31]=0;      // os/arch/type/comp(none)
    const char* name = "kernel";
    for (size_t i=0; name[i]; ++i) h[32+i]=name[i];
    put(4, be32(0));
    put(4, be32(crc32_of(h)));               // hcrc
    return h + payload;
}

static std::string inflate_gzip(const std::string& in) {
    z_stream s{}; inflateInit2(&s, 15+16);
    s.next_in=(Bytef*)in.data(); s.avail_in=(uInt)in.size();
    std::string out; char buf[65536]; int ret;
    do { s.next_out=(Bytef*)buf; s.avail_out=sizeof(buf);
         ret=inflate(&s, Z_NO_FLUSH); out.append(buf, sizeof(buf)-s.avail_out);
    } while (ret==Z_OK); inflateEnd(&s); return out;
}

struct Sandbox {
    std::string dir, image_path, ext, idj;
    std::string image, kernel_text, gz, payload, uimg;
    uint64_t slot = 0x1000, total = 0x2000, ustart, uend;
};

static Sandbox build_sandbox() {
    char tmpl[] = "/tmp/narvi_test.XXXXXX";
    std::string dir = mkdtemp(tmpl);
    Sandbox sb;
    sb.dir = dir;
    sb.image_path = dir + "/firmware.bin";
    sb.ext = sb.image_path + ".extracted";

    for (int i = 0; i < 40; ++i) sb.kernel_text += "hello world, this is a kernel image. ";
    sb.gz = gzip_compress(sb.kernel_text, 9);
    for (int i = 0; i < 60; ++i) sb.payload += "ROOTFS-PAYLOAD-";
    sb.uimg = make_uimage(sb.payload);

    std::string img = sb.gz;
    img.append(sb.slot - sb.gz.size(), '\0');       // 0x00 pad after gzip
    sb.ustart = img.size();                          // 0x1000
    img += sb.uimg;
    sb.uend = img.size();
    img.append(sb.total - sb.uend, (char)0xff);      // 0xff trailing pad
    sb.image = img;
    write_file(sb.image_path, img);

    write_file(sb.ext + "/0x0-gzip/decompressed", sb.kernel_text);
    write_file(sb.ext + "/0x1000-uimage/payload", sb.payload);

    std::string manifest =
        "{\"source\":\"" + sb.image_path + "\",\"extracted\":["
        "{\"offset\":0,\"type\":\"gzip\",\"root\":\"0x0-gzip\",\"status\":\"ok\","
        "\"files\":1,\"dirs\":0,\"symlinks\":0,\"bytes\":" + std::to_string(sb.kernel_text.size()) + ",\"depth\":1},"
        "{\"offset\":4096,\"type\":\"uimage\",\"root\":\"0x1000-uimage\",\"status\":\"ok\","
        "\"files\":1,\"dirs\":0,\"symlinks\":0,\"bytes\":" + std::to_string(sb.payload.size()) + ",\"depth\":1}]}";
    write_file(sb.ext + "/manifest.json", manifest);

    sb.idj = dir + "/identify.json";
    std::string identify =
        "{\"findings\":["
        "{\"offset\":0,\"size\":" + std::to_string(sb.gz.size()) + ",\"type\":\"gzip\","
        "\"category\":\"compression\",\"compression\":\"gzip\",\"endian\":\"little\"},"
        "{\"offset\":4096,\"size\":" + std::to_string(sb.uimg.size()) + ",\"type\":\"uimage\","
        "\"category\":\"bootloader\",\"endian\":\"big\",\"label\":\"kernel\"}],"
        "\"unidentified_regions\":["
        "{\"offset\":" + std::to_string(sb.gz.size()) + ",\"size\":" + std::to_string(sb.slot - sb.gz.size()) + ",\"entropy\":0.0},"
        "{\"offset\":" + std::to_string(sb.uend) + ",\"size\":" + std::to_string(sb.total - sb.uend) + ",\"entropy\":0.0}]}";
    write_file(sb.idj, identify);
    return sb;
}

static void test_sha256_vector() {
    CHECK(sha256_hex("abc") ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          "sha256('abc') matches known vector");
}

static void test_layout_and_identical() {
    Sandbox sb = build_sandbox();
    Recipe r = Recipe::from_extraction(sb.image_path, sb.ext, sb.idj);
    CHECK(r.regions().size() == 2, "two regions planned");
    std::string out = sb.dir + "/out.bin";
    RepackReport rep = Repacker(r).repack(out);
    CHECK(rep.identical, "unchanged repack is byte-identical");
    CHECK(read_file(out) == sb.image, "output bytes equal source");
    fs::remove_all(sb.dir);
}

static void test_save_load() {
    Sandbox sb = build_sandbox();
    Recipe r = Recipe::from_extraction(sb.image_path, sb.ext, sb.idj);
    std::string rp = sb.dir + "/r.json";
    r.save(rp);
    Recipe r2 = Recipe::load(rp);
    std::string out = sb.dir + "/out.bin";
    CHECK(Repacker(r2).repack(out).identical, "save/load preserves byte-identity");
    fs::remove_all(sb.dir);
}

static void test_edit_gzip() {
    Sandbox sb = build_sandbox();
    Recipe r = Recipe::from_extraction(sb.image_path, sb.ext, sb.idj);
    std::string new_content(sb.kernel_text.size(), '\0');  // compresses small -> fits slot
    write_file(sb.ext + "/0x0-gzip/decompressed", new_content);

    Repacker rp(r);
    bool gzip_changed = false, uimage_changed = false;
    for (auto& s : rp.status()) {
        if (s.type == "gzip") gzip_changed = s.changed;
        if (s.type == "uimage") uimage_changed = s.changed;
    }
    CHECK(gzip_changed && !uimage_changed, "only gzip flagged changed");

    std::string out = sb.dir + "/out.bin";
    RepackReport rep = rp.repack(out);
    CHECK(!rep.identical, "edited repack differs from source");
    std::string blob = read_file(out);
    CHECK(blob.size() == sb.image.size(), "fixed layout preserves total size");
    CHECK(inflate_gzip(blob.substr(0, sb.slot)) == new_content, "gzip slot decodes to edit");
    CHECK(blob.substr(sb.ustart, sb.uimg.size()) == sb.uimg, "uimage region untouched");
    fs::remove_all(sb.dir);
}

static void test_edit_uimage() {
    Sandbox sb = build_sandbox();
    Recipe r = Recipe::from_extraction(sb.image_path, sb.ext, sb.idj);
    std::string np = sb.payload;
    for (char& c : np) c ^= 0x5A;   // same length -> fits fixed slot
    write_file(sb.ext + "/0x1000-uimage/payload", np);

    std::string out = sb.dir + "/out.bin";
    Repacker(r).repack(out);
    std::string blob = read_file(out);
    std::string hdr = blob.substr(sb.ustart, UIMAGE_HDR);
    std::string body = blob.substr(sb.ustart + UIMAGE_HDR, np.size());

    auto rd = [&](const std::string& b, size_t o){
        return ((uint32_t)(uint8_t)b[o]<<24)|((uint32_t)(uint8_t)b[o+1]<<16)|
               ((uint32_t)(uint8_t)b[o+2]<<8)|(uint32_t)(uint8_t)b[o+3]; };
    CHECK(rd(hdr,0) == UIMAGE_MAGIC, "uimage magic intact");
    CHECK(rd(hdr,12) == np.size(), "ih_size updated");
    CHECK(rd(hdr,24) == crc32_of(np), "ih_dcrc recomputed");
    CHECK(body == np, "payload written");
    std::string chk = hdr; chk[4]=chk[5]=chk[6]=chk[7]=0;
    CHECK(rd(hdr,4) == crc32_of(chk), "header CRC self-consistent");
    fs::remove_all(sb.dir);
}

static void test_unsupported_edit_errors() {
    Sandbox sb = build_sandbox();
    Recipe r = Recipe::from_extraction(sb.image_path, sb.ext, sb.idj);
    for (auto& s : r.segments) if (s.type == "gzip") s.type = "jffs2";  // no rebuilder
    std::ofstream(sb.ext + "/0x0-gzip/decompressed", std::ios::app | std::ios::binary).put('x');
    bool threw = false;
    try { Repacker(r).repack(sb.dir + "/out.bin"); }
    catch (const std::exception&) { threw = true; }
    CHECK(threw, "edited unsupported region fails loudly");
    fs::remove_all(sb.dir);
}

// moria 0.3.0 identifies standalone legacy .lzma streams as type "lzma"; the
// compressed rebuilder must re-encode them (alone format) rather than refuse.
static void test_lzma_codec_rebuild() {
    std::string data = "standalone lzma unit payload ";
    for (int i = 0; i < 6; i++) data += data;
    std::string enc = compress_by_codec("lzma", data, 6);
    CHECK(lzma_alone_decompress(enc) == data, "lzma round-trips via compress_by_codec");
    CHECK(&rebuilder_for("lzma") != &rebuilder_for("unknown_type_xyz"),
          "lzma dispatches to a real rebuilder, not passthrough");
}

int main() {
    test_sha256_vector();
    test_layout_and_identical();
    test_save_load();
    test_edit_gzip();
    test_edit_uimage();
    test_unsupported_edit_errors();
    test_lzma_codec_rebuild();
    if (failures == 0) { std::cout << "all tests passed\n"; return 0; }
    std::cout << failures << " test(s) failed\n";
    return 1;
}
