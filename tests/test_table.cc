#include <gtest/gtest.h>

#include <atomic>
#include <thread>
#include <vector>

#include "core/credential_table.h"

using namespace gatecrypt;

TEST(Table, InsertFind) {
  CredentialTable t(4);
  EXPECT_TRUE(t.Insert("T1", std::vector<uint8_t>(32, 1), {}));
  EXPECT_FALSE(t.Insert("T1", std::vector<uint8_t>(32, 1), {}));
  auto e = t.Find("T1");
  ASSERT_NE(e, nullptr);
  EXPECT_EQ(e->state.load(), CredState::VALID);
  EXPECT_EQ(t.Find("nope"), nullptr);
}

TEST(Table, ExactlyOnceUnderBurst) {
  CredentialTable t(64);
  ASSERT_TRUE(t.Insert("T-BURST", std::vector<uint8_t>(32, 7), {}));
  auto e = t.Find("T-BURST");
  const int kThreads = 16;
  std::atomic<int> wins{0};
  std::vector<std::thread> th;
  for (int i = 0; i < kThreads; ++i)
    th.emplace_back([&] {
      if (t.TryConsume(e)) wins.fetch_add(1);
    });
  for (auto& x : th) x.join();
  EXPECT_EQ(wins.load(), 1);
  EXPECT_EQ(e->state.load(), CredState::USED);
}

TEST(Table, RevokeTerminal) {
  CredentialTable t(4);
  ASSERT_TRUE(t.Insert("T-R", std::vector<uint8_t>(32, 1), {}));
  EXPECT_TRUE(t.Revoke("T-R"));
  auto e = t.Find("T-R");
  EXPECT_EQ(e->state.load(), CredState::REVOKED);
  EXPECT_FALSE(t.TryConsume(e));  // revoked cannot be consumed
}

TEST(Table, DoubleScanBurstManyTickets) {
  CredentialTable t(64);
  const int kTickets = 200;
  for (int i = 0; i < kTickets; ++i)
    ASSERT_TRUE(t.Insert("T-" + std::to_string(i), std::vector<uint8_t>(32, 1), {}));
  std::atomic<int> wins{0};
  std::vector<std::thread> th;
  for (int k = 0; k < 8; ++k)
    th.emplace_back([&] {
      for (int i = 0; i < kTickets; ++i) {
        auto e = t.Find("T-" + std::to_string(i));
        if (t.TryConsume(e)) wins.fetch_add(1);
      }
    });
  for (auto& x : th) x.join();
  EXPECT_EQ(wins.load(), kTickets);  // exactly one success per ticket
}
