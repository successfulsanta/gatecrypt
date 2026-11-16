#include "storage/merkle.h"

#include <openssl/evp.h>

#include <algorithm>

namespace gatecrypt {

std::vector<uint8_t> Sha256(const uint8_t* data, size_t len) {
  std::vector<uint8_t> out(32);
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  unsigned int olen = 0;
  EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
  if (len) EVP_DigestUpdate(ctx, data, len);
  EVP_DigestFinal_ex(ctx, out.data(), &olen);
  EVP_MD_CTX_free(ctx);
  out.resize(olen);
  return out;
}

static std::vector<uint8_t> HashPair(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
  std::vector<uint8_t> in;
  in.reserve(a.size() + b.size());
  in.insert(in.end(), a.begin(), a.end());
  in.insert(in.end(), b.begin(), b.end());
  return Sha256(in.data(), in.size());
}

void MerkleTree::AddLeaf(const std::vector<uint8_t>& leaf_hash) {
  leaves_.push_back(leaf_hash);
  BuildLevels();
}

void MerkleTree::Rebuild(const std::vector<std::vector<uint8_t>>& leaf_hashes) {
  leaves_ = leaf_hashes;
  std::sort(leaves_.begin(), leaves_.end());
  BuildLevels();
}

void MerkleTree::BuildLevels() {
  levels_.clear();
  if (leaves_.empty()) return;
  levels_.push_back(leaves_);
  std::vector<std::vector<uint8_t>> cur = leaves_;
  while (cur.size() > 1) {
    std::vector<std::vector<uint8_t>> nxt;
    nxt.reserve((cur.size() + 1) / 2);
    for (size_t i = 0; i < cur.size(); i += 2) {
      if (i + 1 < cur.size())
        nxt.push_back(HashPair(cur[i], cur[i + 1]));
      else
        nxt.push_back(HashPair(cur[i], cur[i]));  // duplicate last
    }
    levels_.push_back(nxt);
    cur.swap(nxt);
  }
}

std::vector<uint8_t> MerkleTree::Root() const {
  if (levels_.empty()) return std::vector<uint8_t>(32, 0);
  return levels_.back().front();
}

bool MerkleTree::Proof(size_t index, std::vector<std::vector<uint8_t>>& siblings_out) const {
  siblings_out.clear();
  if (index >= leaves_.size() || levels_.empty()) return false;
  size_t idx = index;
  for (size_t lvl = 0; lvl + 1 < levels_.size(); ++lvl) {
    const auto& cur = levels_[lvl];
    size_t sib = (idx % 2 == 0) ? idx + 1 : idx - 1;
    if (sib >= cur.size()) sib = idx;  // duplicated last
    siblings_out.push_back(cur[sib]);
    idx /= 2;
  }
  return true;
}

bool MerkleTree::VerifyProof(const std::vector<uint8_t>& leaf,
                             const std::vector<std::vector<uint8_t>>& siblings, size_t index,
                             const std::vector<uint8_t>& expected_root) {
  std::vector<uint8_t> cur = leaf;
  size_t idx = index;
  for (auto& sib : siblings) {
    if (idx % 2 == 0)
      cur = HashPair(cur, sib);
    else
      cur = HashPair(sib, cur);
    idx /= 2;
  }
  if (cur.size() != expected_root.size()) return false;
  if (cur.empty()) return false;
  // constant-time compare
  uint8_t diff = 0;
  for (size_t i = 0; i < cur.size(); ++i) diff |= (uint8_t)(cur[i] ^ expected_root[i]);
  return diff == 0;
}

}  // namespace gatecrypt
