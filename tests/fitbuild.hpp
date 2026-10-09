// fitbuild.hpp -- shared test helper: build canonical FIT (.itb) blobs and
// compute FIT hash values. Header-only, inline, so each test binary gets its own
// copy.
#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "narvi/codecs.hpp"
#include "narvi/md5.hpp"
#include "narvi/sha1.hpp"
#include "narvi/sha256.hpp"

namespace fitbuild {

inline std::string be32(uint32_t v) {
    std::string s(4, '\0');
    for (int i = 0; i < 4; i++) s[i] = (char)(uint8_t)(v >> (8 * (3 - i)));
    return s;
}
inline std::string sha256_raw(const std::string& d) {
    std::string hex = narvi::sha256_hex(d), raw(hex.size() / 2, '\0');
    auto nyb = [](char c){ return (c>='0'&&c<='9')?c-'0':(c>='a'&&c<='f')?c-'a'+10:0; };
    for (size_t i = 0; i < raw.size(); i++) raw[i] = (char)((nyb(hex[2*i])<<4)|nyb(hex[2*i+1]));
    return raw;
}
inline std::string fit_hash(const std::string& algo, const std::string& d) {
    if (algo == "crc32") return be32(narvi::crc32_of(d));   // FIT stores crc32 big-endian
    if (algo == "md5") return narvi::md5_bytes(d);
    if (algo == "sha1") return narvi::sha1_bytes(d);
    return sha256_raw(d);
}
inline std::string pad4(const std::string& b) { return b + std::string((4 - b.size() % 4) % 4, '\0'); }

struct FitImage { std::string name, data; std::vector<std::pair<std::string,std::string>> hashes; bool sig; };
struct BuiltFit {
    std::string bytes;
    std::map<std::string, std::pair<uint64_t,uint64_t>> data_abs;   // name -> (off,len)
    std::map<std::string, std::pair<uint64_t,uint64_t>> hash_abs;   // "name|algo" -> (off,len)
};

inline BuiltFit build_fit(const std::vector<FitImage>& images) {
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
    endn();
    begin("configurations");
    prop("default", std::string("conf-1\0", 7));
    endn();
    endn();
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

}  // namespace fitbuild
