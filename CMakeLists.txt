cmake_minimum_required(VERSION 3.25)
project(gatecrypt VERSION 0.1.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Warnings as errors (gcc/clang)
add_compile_options(
  $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall>
  $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wextra>
  $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wpedantic>
  $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Werror>
  $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wshadow>
  $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wno-unused-parameter>
  # GCC 12+ -O2/-O3 false positive on inlined stdlib internals
  # (free-nonheap-object fires on vector code, not ours). Keep as warning.
  $<$<CXX_COMPILER_ID:GNU>:-Wno-error=free-nonheap-object>
  # gtest 1.14 trips -Wcharacter-conversion (char8_t) under Clang;
  # third-party header, keep as warning so -Werror stays for our code.
  $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wno-error=character-conversion>
)

find_package(OpenSSL 3.0 REQUIRED)

option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(ENABLE_TSAN "Enable ThreadSanitizer" OFF)
option(ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(BUILD_FUZZ "Build libFuzzer targets (clang only)" OFF)

if(ENABLE_ASAN)
  add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address)
endif()
if(ENABLE_TSAN)
  add_compile_options(-fsanitize=thread -fno-omit-frame-pointer)
  add_link_options(-fsanitize=thread)
endif()
if(ENABLE_UBSAN)
  add_compile_options(-fsanitize=undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=undefined)
endif()

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/v1.14.0.zip
)
# Don't install gtest by default
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# ---- core library ----
set(GATECRYPT_SOURCES
  src/config/config.cc
  src/observability/logger.cc
  src/observability/metrics.cc
  src/crypto/secure.cc
  src/crypto/software_key_store.cc
  src/crypto/nonce_manager.cc
  src/protocol/framing.cc
  src/core/credential_table.cc
  src/core/verify_engine.cc
  src/storage/crc32c.cc
  src/storage/wal.cc
  src/storage/merkle.cc
  src/storage/revocation.cc
  src/storage/sync.cc
  src/net/epoll_server.cc
  src/net/tls.cc
  src/observability/metrics_server.cc
)

add_library(gatecrypt STATIC ${GATECRYPT_SOURCES})
target_include_directories(gatecrypt PUBLIC src)
target_link_libraries(gatecrypt PUBLIC OpenSSL::SSL OpenSSL::Crypto pthread)

# ---- daemons / tools ----
add_executable(gatecryptd src/daemon/main.cc)
target_link_libraries(gatecryptd PRIVATE gatecrypt)

add_executable(gatecrypt-issue src/tools/issue_cli.cc)
target_link_libraries(gatecrypt-issue PRIVATE gatecrypt)

add_executable(gatecrypt-loadgen src/tools/loadgen.cc)
target_link_libraries(gatecrypt-loadgen PRIVATE gatecrypt)

# ---- tests ----
enable_testing()
include(GoogleTest)

set(GATECRYPT_TESTS
  tests/test_smoke.cc
  tests/test_crypto.cc
  tests/test_protocol.cc
  tests/test_ring.cc
  tests/test_table.cc
  tests/test_wal.cc
  tests/test_merkle.cc
  tests/test_verify.cc
)

add_executable(gatecrypt_tests ${GATECRYPT_TESTS})
target_link_libraries(gatecrypt_tests PRIVATE gatecrypt GTest::gtest_main)
gtest_discover_tests(gatecrypt_tests)

# ---- fuzz targets (clang + libFuzzer) ----
if(BUILD_FUZZ)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "BUILD_FUZZ requires Clang")
  endif()
  add_executable(fuzz_protocol fuzz/fuzz_protocol.cc)
  target_link_libraries(fuzz_protocol PRIVATE gatecrypt)
  target_compile_options(fuzz_protocol PRIVATE -fsanitize=fuzzer,address)
  target_link_options(fuzz_protocol PRIVATE -fsanitize=fuzzer,address)

  add_executable(fuzz_wal fuzz/fuzz_wal.cc)
  target_link_libraries(fuzz_wal PRIVATE gatecrypt)
  target_compile_options(fuzz_wal PRIVATE -fsanitize=fuzzer,address)
  target_link_options(fuzz_wal PRIVATE -fsanitize=fuzzer,address)
endif()
