#pragma once
#include <cstddef>
#include <cstdint>
namespace gatecrypt {
// CRC32C (Castagnoli) software implementation.
uint32_t Crc32c(const uint8_t* data, size_t len);
uint32_t Crc32cExtend(uint32_t crc, const uint8_t* data, size_t len);
}  // namespace gatecrypt
