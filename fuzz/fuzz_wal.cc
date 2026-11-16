#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "storage/crc32c.h"
#include "storage/wal.h"

// libFuzzer entry: WAL replay must handle arbitrary bytes without crash.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 8) return 0;
  char dir[] = "/tmp/gc-fuzz-wal-XXXXXX";
  if (!mkdtemp(dir)) return 0;
  std::string seg = std::string(dir) + "/seg-000000.wal";
  {
    FILE* f = fopen(seg.c_str(), "wb");
    if (!f) {
      rmdir(dir);
      return 0;
    }
    fwrite(data, 1, size, f);
    fclose(f);
  }
  gatecrypt::Wal w(dir, 1 << 20);
  std::string err;
  std::vector<gatecrypt::WalRecord> recs;
  w.Replay(
      [&](const gatecrypt::WalRecord& r) {
        recs.push_back(r);
        return true;
      },
      err);
  // CRC helper on fuzz bytes (no crash).
  volatile uint32_t c = gatecrypt::Crc32c(data, size);
  (void)c;
  remove(seg.c_str());
  rmdir(dir);
  return 0;
}
