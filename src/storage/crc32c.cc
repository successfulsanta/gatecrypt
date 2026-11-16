#include "storage/crc32c.h"

namespace gatecrypt {
namespace {
// Castagnoli polynomial reflected: 0x1EDC6F41 -> reflected 0x82F63B78
alignas(64) uint32_t kTable[256];
bool kInit = false;
void InitTable() {
  for (uint32_t i = 0; i < 256; ++i) {
    uint32_t c = i;
    for (int k = 0; k < 8; ++k) c = (c & 1) ? (0x82F63B78u ^ (c >> 1)) : (c >> 1);
    kTable[i] = c;
  }
  kInit = true;
}
}  // namespace

uint32_t Crc32cExtend(uint32_t crc, const uint8_t* data, size_t len) {
  if (!kInit) InitTable();
  crc = ~crc;
  for (size_t i = 0; i < len; ++i) crc = kTable[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
  return ~crc;
}

uint32_t Crc32c(const uint8_t* data, size_t len) { return Crc32cExtend(0, data, len); }

}  // namespace gatecrypt
