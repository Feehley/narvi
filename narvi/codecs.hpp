// codecs.hpp -- compression and CRC, using the same libraries moria links
// (zlib, liblzma, libzstd, liblz4). Only used when a region is EDITED.
#pragma once
#include <cstdint>
#include <string>

namespace narvi {

uint32_t crc32_of(const std::string& data);  // standard CRC-32 (zlib)

std::string gzip_compress(const std::string& data, int level = 9);
std::string gzip_decompress(const std::string& data);   // inflate a gzip stream fully
std::string xz_compress(const std::string& data, int preset = 6);
std::string lzma_alone_compress(const std::string& data, int preset = 6);  // .lzma "alone" (FIT lzma)
std::string lzma_alone_decompress(const std::string& data);
std::string zstd_compress(const std::string& data, int level = 19);
std::string lz4_compress(const std::string& data, int level = 9);

// Length of the compressed stream that starts at `off`, found by decoding it.
// Recovers the span moria computes (Extracted.consumed) but omits from the
// manifest. Returns -1 when it cannot be determined here.
long gzip_stream_span(const std::string& data, uint64_t off);

std::string compress_by_codec(const std::string& codec, const std::string& data, int level);

}  // namespace narvi
