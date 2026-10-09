#include "narvi/codecs.hpp"

#include <stdexcept>

#include <zlib.h>
#include <lzma.h>
#include <zstd.h>
#include <lz4frame.h>

namespace narvi {

uint32_t crc32_of(const std::string& data) {
    return (uint32_t)crc32(0L, (const Bytef*)data.data(), (uInt)data.size());
}

std::string gzip_compress(const std::string& data, int level) {
    z_stream s{};
    if (deflateInit2(&s, level, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
        throw std::runtime_error("gzip: deflateInit2 failed");
    s.next_in = (Bytef*)data.data();
    s.avail_in = (uInt)data.size();
    std::string out;
    char buf[1 << 16];
    int ret;
    do {
        s.next_out = (Bytef*)buf;
        s.avail_out = sizeof(buf);
        ret = deflate(&s, Z_FINISH);
        out.append(buf, sizeof(buf) - s.avail_out);
    } while (ret != Z_STREAM_END);
    deflateEnd(&s);
    return out;
}

std::string gzip_decompress(const std::string& data) {
    z_stream s{};
    if (inflateInit2(&s, 15 + 16) != Z_OK) throw std::runtime_error("gzip: inflateInit2 failed");
    s.next_in = (Bytef*)data.data();
    s.avail_in = (uInt)data.size();
    std::string out;
    char buf[1 << 16];
    int ret;
    do {
        s.next_out = (Bytef*)buf;
        s.avail_out = sizeof(buf);
        ret = inflate(&s, Z_NO_FLUSH);
        if (ret == Z_DATA_ERROR || ret == Z_MEM_ERROR || ret == Z_NEED_DICT) {
            inflateEnd(&s);
            throw std::runtime_error("gzip: inflate failed");
        }
        out.append(buf, sizeof(buf) - s.avail_out);
    } while (ret != Z_STREAM_END);
    inflateEnd(&s);
    return out;
}

long gzip_stream_span(const std::string& data, uint64_t off) {
    z_stream s{};
    if (inflateInit2(&s, 15 + 16) != Z_OK) return -1;
    s.next_in = (Bytef*)data.data() + off;
    s.avail_in = (uInt)(data.size() - off);
    char buf[1 << 16];
    int ret;
    do {
        s.next_out = (Bytef*)buf;
        s.avail_out = sizeof(buf);
        ret = inflate(&s, Z_NO_FLUSH);
        if (ret == Z_DATA_ERROR || ret == Z_MEM_ERROR || ret == Z_NEED_DICT) {
            inflateEnd(&s);
            return -1;
        }
    } while (ret != Z_STREAM_END && s.avail_in > 0);
    long consumed = (ret == Z_STREAM_END) ? (long)s.total_in : -1;
    inflateEnd(&s);
    return consumed;
}

std::string xz_compress(const std::string& data, int preset) {
    size_t cap = lzma_stream_buffer_bound(data.size());
    std::string out(cap, '\0');
    size_t pos = 0;
    lzma_ret r = lzma_easy_buffer_encode((uint32_t)preset, LZMA_CHECK_CRC64, nullptr,
                                         (const uint8_t*)data.data(), data.size(),
                                         (uint8_t*)out.data(), &pos, cap);
    if (r != LZMA_OK) throw std::runtime_error("xz: encode failed");
    out.resize(pos);
    return out;
}

std::string lzma_alone_compress(const std::string& data, int preset) {
    lzma_options_lzma opt;
    if (lzma_lzma_preset(&opt, (uint32_t)preset)) throw std::runtime_error("lzma: preset failed");
    lzma_stream strm = LZMA_STREAM_INIT;
    if (lzma_alone_encoder(&strm, &opt) != LZMA_OK) throw std::runtime_error("lzma: alone encoder init failed");
    strm.next_in = (const uint8_t*)data.data();
    strm.avail_in = data.size();
    std::string out; char buf[1 << 16];
    lzma_ret r;
    do {
        strm.next_out = (uint8_t*)buf; strm.avail_out = sizeof(buf);
        r = lzma_code(&strm, LZMA_FINISH);
        if (r != LZMA_OK && r != LZMA_STREAM_END) { lzma_end(&strm); throw std::runtime_error("lzma: encode failed"); }
        out.append(buf, sizeof(buf) - strm.avail_out);
    } while (r != LZMA_STREAM_END);
    lzma_end(&strm);
    return out;
}

std::string lzma_alone_decompress(const std::string& data) {
    lzma_stream strm = LZMA_STREAM_INIT;
    if (lzma_alone_decoder(&strm, UINT64_MAX) != LZMA_OK) throw std::runtime_error("lzma: alone decoder init failed");
    strm.next_in = (const uint8_t*)data.data();
    strm.avail_in = data.size();
    std::string out; char buf[1 << 16];
    lzma_ret r;
    do {
        strm.next_out = (uint8_t*)buf; strm.avail_out = sizeof(buf);
        r = lzma_code(&strm, LZMA_FINISH);
        if (r != LZMA_OK && r != LZMA_STREAM_END) { lzma_end(&strm); throw std::runtime_error("lzma: decode failed"); }
        out.append(buf, sizeof(buf) - strm.avail_out);
    } while (r != LZMA_STREAM_END);
    lzma_end(&strm);
    return out;
}

std::string zstd_compress(const std::string& data, int level) {
    size_t cap = ZSTD_compressBound(data.size());
    std::string out(cap, '\0');
    size_t n = ZSTD_compress(out.data(), cap, data.data(), data.size(), level);
    if (ZSTD_isError(n)) throw std::runtime_error("zstd: compress failed");
    out.resize(n);
    return out;
}

std::string lz4_compress(const std::string& data, int level) {
    LZ4F_preferences_t prefs{};
    prefs.compressionLevel = level;
    size_t cap = LZ4F_compressFrameBound(data.size(), &prefs);
    std::string out(cap, '\0');
    size_t n = LZ4F_compressFrame(out.data(), cap, data.data(), data.size(), &prefs);
    if (LZ4F_isError(n)) throw std::runtime_error("lz4: compress failed");
    out.resize(n);
    return out;
}

std::string compress_by_codec(const std::string& codec, const std::string& data, int level) {
    if (codec == "gzip") return gzip_compress(data, level);
    if (codec == "lzma") return lzma_alone_compress(data, level);   // legacy standalone .lzma
    if (codec == "xz")   return xz_compress(data, level);
    if (codec == "zstd") return zstd_compress(data, level);
    if (codec == "lz4")  return lz4_compress(data, level);
    throw std::runtime_error("no compressor for codec '" + codec + "'");
}

}  // namespace narvi
