// sha1.hpp -- compact SHA-1 (public domain style), header-only.
// Only needed to recompute FIT `sha1` hash nodes. Self-tested in the suite.
#pragma once
#include <cstdint>
#include <cstring>
#include <string>

namespace narvi {

class Sha1 {
public:
    Sha1() { reset(); }
    void reset() {
        len_ = 0; buflen_ = 0;
        h_[0] = 0x67452301; h_[1] = 0xEFCDAB89; h_[2] = 0x98BADCFE;
        h_[3] = 0x10325476; h_[4] = 0xC3D2E1F0;
    }
    void update(const void* data, size_t n) {
        const uint8_t* p = static_cast<const uint8_t*>(data);
        len_ += n;
        while (n--) {
            buf_[buflen_++] = *p++;
            if (buflen_ == 64) { block(buf_); buflen_ = 0; }
        }
    }
    void update(const std::string& s) { update(s.data(), s.size()); }

    std::string digest() {
        uint64_t bits = len_ * 8;
        uint8_t pad = 0x80;
        update(&pad, 1);
        uint8_t zero = 0;
        while (buflen_ != 56) update(&zero, 1);
        uint8_t lenbuf[8];
        for (int i = 0; i < 8; i++) lenbuf[i] = (uint8_t)(bits >> (8 * (7 - i)));  // big-endian
        update(lenbuf, 8);
        std::string out(20, '\0');
        for (int i = 0; i < 5; i++) {
            out[i * 4 + 0] = (char)(uint8_t)(h_[i] >> 24);
            out[i * 4 + 1] = (char)(uint8_t)(h_[i] >> 16);
            out[i * 4 + 2] = (char)(uint8_t)(h_[i] >> 8);
            out[i * 4 + 3] = (char)(uint8_t)(h_[i]);
        }
        return out;
    }

private:
    static uint32_t rotl(uint32_t x, int c) { return (x << c) | (x >> (32 - c)); }

    void block(const uint8_t* p) {
        uint32_t w[80];
        for (int i = 0; i < 16; i++)
            w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) |
                   ((uint32_t)p[i*4+2] << 8) | (uint32_t)p[i*4+3];
        for (int i = 16; i < 80; i++)
            w[i] = rotl(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
        uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4];
        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20)      { f = (b & c) | (~b & d);            k = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ d;                     k = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d);   k = 0x8F1BBCDC; }
            else             { f = b ^ c ^ d;                     k = 0xCA62C1D6; }
            uint32_t t = rotl(a, 5) + f + e + k + w[i];
            e = d; d = c; c = rotl(b, 30); b = a; a = t;
        }
        h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d; h_[4] += e;
    }

    uint32_t h_[5];
    uint64_t len_;
    uint8_t buf_[64];
    size_t buflen_;
};

inline std::string sha1_bytes(const std::string& data) {
    Sha1 s; s.update(data); return s.digest();
}

}  // namespace narvi
