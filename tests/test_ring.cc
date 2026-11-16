#include <gtest/gtest.h>

#include <atomic>
#include <thread>
#include <vector>

#include "core/ring_buffer.h"

using namespace gatecrypt;

TEST(Ring, PushPopSingle) {
  RingBuffer<int> r(8);
  EXPECT_TRUE(r.TryPush(42));
  int v = 0;
  EXPECT_TRUE(r.TryPop(v));
  EXPECT_EQ(v, 42);
  EXPECT_FALSE(r.TryPop(v));
}

TEST(Ring, FullReturnsFalse) {
  RingBuffer<int> r(4);
  for (int i = 0; i < 4; ++i) EXPECT_TRUE(r.TryPush(i));
  EXPECT_FALSE(r.TryPush(99));  // backpressure signal, never blocks
}

TEST(Ring, FifoOrder) {
  RingBuffer<int> r(16);
  for (int i = 0; i < 10; ++i) EXPECT_TRUE(r.TryPush(i));
  for (int i = 0; i < 10; ++i) {
    int v = -1;
    ASSERT_TRUE(r.TryPop(v));
    EXPECT_EQ(v, i);
  }
}

TEST(Ring, RoundsUpPowerOfTwo) {
  RingBuffer<int> r(100);
  EXPECT_EQ(r.capacity(), 128u);
}

TEST(Ring, MpmcSoak) {
  RingBuffer<int> r(1024);
  const int kProducers = 4, kPer = 5000;
  std::atomic<int> consumed{0};
  std::atomic<bool> stop{false};
  std::atomic<long long> sum{0};
  std::thread c([&] {
    int v;
    while (!stop.load() || r.ApproxSize() > 0) {
      if (r.TryPop(v)) {
        sum.fetch_add(v);
        consumed.fetch_add(1);
      }
    }
  });
  std::vector<std::thread> ps;
  for (int p = 0; p < kProducers; ++p)
    ps.emplace_back([&, p] {
      for (int i = 0; i < kPer; ++i) {
        while (!r.TryPush(p * kPer + i)) {
        }
      }
    });
  for (auto& t : ps) t.join();
  stop.store(true);
  c.join();
  EXPECT_EQ(consumed.load(), kProducers * kPer);
  long long expect = 0;
  for (int i = 0; i < kProducers * kPer; ++i) expect += i;
  EXPECT_EQ(sum.load(), expect);
}
