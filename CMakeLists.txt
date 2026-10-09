cmake_minimum_required(VERSION 3.20)
project(narvi VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra -Wpedantic)

option(NARVI_SANITIZE "Build with ASan+UBSan" OFF)
if(NARVI_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
  add_link_options(-fsanitize=address,undefined)
endif()

# Same libraries moria links (zlib/lzma/zstd/lz4). Only used to re-encode
# regions that were actually edited.
find_package(ZLIB REQUIRED)
find_library(LZMA_LIB lzma REQUIRED)
find_library(ZSTD_LIB zstd REQUIRED)
find_library(LZ4_LIB lz4 REQUIRED)

add_library(narvi_core STATIC
  narvi/codecs.cpp
  narvi/rebuilders.cpp
  narvi/recipe.cpp
  narvi/repacker.cpp
  narvi/verify.cpp
  narvi/fixups.cpp
  narvi/fdt.cpp)
target_include_directories(narvi_core PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(narvi_core PUBLIC ZLIB::ZLIB ${LZMA_LIB} ${ZSTD_LIB} ${LZ4_LIB})

add_executable(narvi narvi/cli.cpp)
target_link_libraries(narvi PRIVATE narvi_core)

enable_testing()
add_executable(narvi_tests tests/roundtrip.cpp)
target_link_libraries(narvi_tests PRIVATE narvi_core ZLIB::ZLIB)
add_test(NAME roundtrip COMMAND narvi_tests)

add_executable(narvi_nested_tests tests/nested.cpp)
target_link_libraries(narvi_nested_tests PRIVATE narvi_core ZLIB::ZLIB)
add_test(NAME nested COMMAND narvi_nested_tests)

add_executable(narvi_verify_tests tests/verify.cpp)
target_link_libraries(narvi_verify_tests PRIVATE narvi_core ZLIB::ZLIB)
add_test(NAME verify COMMAND narvi_verify_tests)

add_executable(narvi_fixups_tests tests/fixups.cpp)
target_link_libraries(narvi_fixups_tests PRIVATE narvi_core ZLIB::ZLIB)
add_test(NAME fixups COMMAND narvi_fixups_tests)

add_executable(narvi_fdt_tests tests/fdt.cpp)
target_link_libraries(narvi_fdt_tests PRIVATE narvi_core ZLIB::ZLIB)
add_test(NAME fdt COMMAND narvi_fdt_tests)

add_executable(narvi_fitrebuild_tests tests/fitrebuild.cpp)
target_link_libraries(narvi_fitrebuild_tests PRIVATE narvi_core ZLIB::ZLIB)
add_test(NAME fitrebuild COMMAND narvi_fitrebuild_tests)

add_executable(narvi_cpio_tests tests/cpio.cpp)
target_link_libraries(narvi_cpio_tests PRIVATE narvi_core ZLIB::ZLIB)
add_test(NAME cpio COMMAND narvi_cpio_tests)
