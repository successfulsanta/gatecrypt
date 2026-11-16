#include <gtest/gtest.h>

#include <cstdio>
#include <string>
#include <vector>

#include "storage/wal.h"

using namespace gatecrypt;

static std::string TmpDir() {
  char t[] = "/tmp/gc-wal-test-XXXXXX";
  if (!mkdtemp(t)) return "/tmp/gc-wal-fallback";
  return t;
}

TEST(Wal, AppendReplay) {
  std::string dir = TmpDir();
  Wal w(dir, 1 << 20);
  std::string err;
  ASSERT_TRUE(w.Open(err)) << err;
  uint64_t s1 = 0, s2 = 0;
  ASSERT_TRUE(w.Append(WalRecordType::ISSUE, "T1", s1, err)) << err;
  ASSERT_TRUE(w.Append(WalRecordType::USE, "T1", s2, err)) << err;
  EXPECT_EQ(s2, s1 + 1);
  std::vector<WalRecord> recs;
  ASSERT_TRUE(w.Replay(
      [&](const WalRecord& r) {
        recs.push_back(r);
        return true;
      },
      err))
      << err;
  ASSERT_EQ(recs.size(), 2u);
  EXPECT_EQ(recs[0].seqno, s1);
  EXPECT_EQ(recs[1].seqno, s2);
  EXPECT_EQ(recs[1].type, WalRecordType::USE);
}

TEST(Wal, TornTailTruncated) {
  std::string dir = TmpDir();
  {
    Wal w(dir, 1 << 20);
    std::string err;
    ASSERT_TRUE(w.Open(err)) << err;
    uint64_t s = 0;
    ASSERT_TRUE(w.Append(WalRecordType::USE, "T-good", s, err)) << err;
    // Append garbage torn tail manually.
    FILE* f = fopen((dir + "/seg-000000.wal").c_str(), "ab");
    ASSERT_NE(f, nullptr);
    const char torn[] = {0x31, 0x4c, 0x41};  // partial header
    fwrite(torn, 1, sizeof(torn), f);
    fclose(f);
  }
  Wal w2(dir, 1 << 20);
  std::string err;
  std::vector<WalRecord> recs;
  ASSERT_TRUE(w2.Replay(
      [&](const WalRecord& r) {
        recs.push_back(r);
        return true;
      },
      err))
      << err;
  ASSERT_EQ(recs.size(), 1u);
  EXPECT_EQ(std::string(recs[0].payload.begin(), recs[0].payload.end()), "T-good");
}

TEST(Wal, CrcMismatchTruncates) {
  std::string dir = TmpDir();
  {
    Wal w(dir, 1 << 20);
    std::string err;
    ASSERT_TRUE(w.Open(err)) << err;
    uint64_t s = 0;
    ASSERT_TRUE(w.Append(WalRecordType::USE, "T-1", s, err)) << err;
    ASSERT_TRUE(w.Append(WalRecordType::USE, "T-2", s, err)) << err;
    w.Close();
    // Corrupt last record's payload byte.
    FILE* f = fopen((dir + "/seg-000000.wal").c_str(), "r+b");
    ASSERT_NE(f, nullptr);
    fseek(f, -5, SEEK_END);
    char b = (char)0xFF;
    fwrite(&b, 1, 1, f);
    fclose(f);
  }
  Wal w2(dir, 1 << 20);
  std::string err;
  std::vector<WalRecord> recs;
  ASSERT_TRUE(w2.Replay(
      [&](const WalRecord& r) {
        recs.push_back(r);
        return true;
      },
      err))
      << err;
  ASSERT_EQ(recs.size(), 1u);  // only first survives
}

TEST(Wal, Segments) {
  std::string dir = TmpDir();
  Wal w(dir, 64);  // tiny segments to force rotation
  std::string err;
  ASSERT_TRUE(w.Open(err)) << err;
  for (int i = 0; i < 10; ++i) {
    uint64_t s = 0;
    ASSERT_TRUE(w.Append(WalRecordType::USE, "ticket-" + std::to_string(i), s, err)) << err;
  }
  EXPECT_GT(w.SegmentCount(), 1u);
  std::vector<WalRecord> recs;
  ASSERT_TRUE(w.Replay(
      [&](const WalRecord& r) {
        recs.push_back(r);
        return true;
      },
      err))
      << err;
  EXPECT_EQ(recs.size(), 10u);
  // seqnos contiguous
  for (size_t i = 1; i < recs.size(); ++i) EXPECT_EQ(recs[i].seqno, recs[i - 1].seqno + 1);
}
