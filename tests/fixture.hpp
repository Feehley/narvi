// fixture.hpp -- shared test fixture: a firmware image whose first region is a
// uImage wrapping a gzip stream (a depth-2 child), plus a sibling top-level
// gzip. Used by the nested-repack and verify test suites.
#pragma once
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <zlib.h>

#include "narvi/codecs.hpp"
#include "narvi/rebuilders.hpp"

namespace fixture {

namespace fs = std::filesystem;
using namespace narvi;

inline void write_file(const std::string& p, const std::string& data) {
    fs::create_directories(fs::path(p).parent_path());
    std::ofstream f(p, std::ios::binary);
    f.write(data.data(), (std::streamsize)data.size());
}

inline std::string slurp(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

inline std::string be32(uint32_t v) {
    std::string s(4, '\0');
    s[0] = (char)(v >> 24); s[1] = (char)(v >> 16); s[2] = (char)(v >> 8); s[3] = (char)v;
    return s;
}
inline uint32_t rd_be32(const std::string& b, size_t off) {
    return ((uint32_t)(uint8_t)b[off] << 24) | ((uint32_t)(uint8_t)b[off + 1] << 16) |
           ((uint32_t)(uint8_t)b[off + 2] << 8) | (uint32_t)(uint8_t)b[off + 3];
}

// 64-byte uImage header wrapping `payload`, comp field = gzip.
inline std::string make_uimage(const std::string& payload) {
    std::string h(UIMAGE_HDR, '\0');
    auto put = [&](size_t off, const std::string& v) { for (size_t i = 0; i < 4; i++) h[off + i] = v[i]; };
    put(0, be32(UIMAGE_MAGIC));
    put(8, be32(0));                                    // ih_time
    put(12, be32((uint32_t)payload.size()));            // ih_size
    put(24, be32(crc32_of(payload)));                   // ih_dcrc
    h[28] = 5; h[29] = 2; h[30] = 2; h[31] = 1;         // os / arch / type / comp=gzip
    const char* name = "kernel";
    std::memcpy(&h[32], name, std::strlen(name));
    put(4, be32(crc32_of(h)));                          // ih_hcrc over header w/ hcrc=0
    return h + payload;
}

inline std::string gunzip(const std::string& in) {
    z_stream zs{};
    if (inflateInit2(&zs, 31) != Z_OK) throw std::runtime_error("inflateInit2");
    zs.next_in = (Bytef*)in.data();
    zs.avail_in = (uInt)in.size();
    std::string out;
    char buf[8192];
    int rc;
    do {
        zs.next_out = (Bytef*)buf;
        zs.avail_out = sizeof(buf);
        rc = inflate(&zs, Z_NO_FLUSH);
        if (rc != Z_OK && rc != Z_STREAM_END) { inflateEnd(&zs); throw std::runtime_error("inflate"); }
        out.append(buf, sizeof(buf) - zs.avail_out);
    } while (rc != Z_STREAM_END);
    inflateEnd(&zs);
    return out;
}

struct Meta {
    std::string image, kernel, gz, uimg, other, gz2;
    uint64_t slot = 0x2000, b_off = 0x2000, b_len = 0;
    std::string image_path, ext, idj;
};

inline std::string mktemp_dir() {
    std::string base = (fs::temp_directory_path() / "narvi_fx_XXXXXX").string();
    std::vector<char> tmpl(base.begin(), base.end());
    tmpl.push_back('\0');
    char* d = mkdtemp(tmpl.data());
    if (!d) throw std::runtime_error("mkdtemp");
    return std::string(d);
}

inline Meta build_sandbox(const std::string& td) {
    Meta m;
    std::string kernel;
    for (int i = 0; i < 50; i++) kernel += "inner kernel payload, quite compressible ";
    std::string gz = gzip_compress(kernel, 9);
    std::string uimg = make_uimage(gz);

    std::string other;
    for (int i = 0; i < 20; i++) other += "sibling region contents ";
    std::string gz2 = gzip_compress(other, 9);

    const uint64_t SLOT = 0x2000, TAIL = 0x3000;
    std::string img = uimg;
    img.append(SLOT - img.size(), '\0');
    uint64_t b_off = img.size();
    img += gz2;
    img.append(TAIL - img.size(), (char)0xff);

    m.image_path = (fs::path(td) / "firmware.bin").string();
    write_file(m.image_path, img);

    m.ext = m.image_path + ".extracted";
    write_file(m.ext + "/0x0-uimage/payload", gz);
    write_file(m.ext + "/0x0-uimage/payload.extracted/0x0-gzip/decompressed", kernel);
    write_file(m.ext + "/0x2000-gzip/decompressed", other);

    std::string manifest = std::string("{\"source\":\"") + m.image_path + "\",\"extracted\":[";
    manifest += "{\"offset\":0,\"type\":\"uimage\",\"root\":\"0x0-uimage\",\"status\":\"ok\",\"depth\":1},";
    manifest += "{\"offset\":0,\"type\":\"gzip\",\"root\":\"0x0-uimage/payload.extracted/0x0-gzip\",\"status\":\"ok\",\"depth\":2},";
    manifest += "{\"offset\":" + std::to_string(b_off) + ",\"type\":\"gzip\",\"root\":\"0x2000-gzip\",\"status\":\"ok\",\"depth\":1}";
    manifest += "]}";
    write_file(m.ext + "/manifest.json", manifest);

    std::string identify = std::string("{\"findings\":[") +
        "{\"offset\":0,\"size\":" + std::to_string(uimg.size()) + ",\"type\":\"uimage\",\"endian\":\"big\"}," +
        "{\"offset\":" + std::to_string(b_off) + ",\"size\":" + std::to_string(gz2.size()) +
        ",\"type\":\"gzip\",\"compression\":\"gzip\"}]}";
    m.idj = (fs::path(td) / "identify.json").string();
    write_file(m.idj, identify);

    m.image = img; m.kernel = kernel; m.gz = gz; m.uimg = uimg;
    m.other = other; m.gz2 = gz2; m.slot = SLOT; m.b_off = b_off; m.b_len = gz2.size();
    return m;
}

}  // namespace fixture
