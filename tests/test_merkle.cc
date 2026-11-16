#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <vector>

#include "storage/merkle.h"
#include "storage/sync.h"

using namespace gatecrypt;

TEST(Merkle, EmptyRootZero) {
  MerkleTree t;
  EXPECT_EQ(t.Root(), std::vector<uint8_t>(32, 0));
}

TEST(Merkle, ProveVerify) {
  MerkleTree t;
  std::vector<std::vector<uint8_t>> leaves;
  for (int i = 0; i < 8; ++i) {
    std::string s = "ticket-" + std::to_string(i);
    leaves.push_back(Sha256((uint8_t*)s.data(), s.size()));
  }
  t.Rebuild(leaves);
  // leaves_ sorted inside Rebuild; find index of our leaf by comparing
  auto root = t.Root();
  EXPECT_EQ(root.size(), 32u);
  // Prove each leaf (need sorted order index).
  std::vector<std::vector<uint8_t>> sorted = leaves;
  std::sort(sorted.begin(), sorted.end());
  for (size_t i = 0; i < sorted.size(); ++i) {
    std::vector<std::vector<uint8_t>> sibs;
    ASSERT_TRUE(t.Proof(i, sibs));
    EXPECT_TRUE(MerkleTree::VerifyProof(sorted[i], sibs, i, root));
    // tampered leaf fails
    auto bad = sorted[i];
    bad[0] ^= 1;
    EXPECT_FALSE(MerkleTree::VerifyProof(bad, sibs, i, root));
  }
}

TEST(Merkle, RebuildDeterministic) {
  MerkleTree a, b;
  std::vector<std::vector<uint8_t>> l1, l2;
  for (int i = 7; i >= 0; --i) {
    std::string s = "t" + std::to_string(i);
    l1.push_back(Sha256((uint8_t*)s.data(), s.size()));
  }
  for (int i = 0; i < 8; ++i) {
    std::string s = "t" + std::to_string(i);
    l2.push_back(Sha256((uint8_t*)s.data(), s.size()));
  }
  a.Rebuild(l1);
  b.Rebuild(l2);
  EXPECT_EQ(a.Root(), b.Root());
}

TEST(Sync, MergeUnionNoConflict) {
  std::vector<std::string> local = {"a", "b"};
  std::vector<std::string> remote = {"c"};
  std::vector<std::string> mark, lost;
  MergeUsedSets(local, 1, remote, 2, mark, lost);
  EXPECT_EQ(mark, remote);
  EXPECT_TRUE(lost.empty());
}

TEST(Sync, ConflictLowestGateWins) {
  std::vector<std::string> local = {"x"};
  std::vector<std::string> remote = {"x"};
  std::vector<std::string> mark, lost;
  // local gate 5, remote 2 -> remote wins, local flagged lost
  MergeUsedSets(local, 5, remote, 2, mark, lost);
  ASSERT_EQ(lost.size(), 1u);
  EXPECT_EQ(lost[0], "x");
  // reversed: local wins, no loss
  MergeUsedSets(local, 1, remote, 9, mark, lost);
  EXPECT_TRUE(lost.empty());
}
