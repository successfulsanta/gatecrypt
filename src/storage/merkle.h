#pragma once
// Merkle accumulator over used credential IDs + versioned revocation list.
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace gatecrypt {

std::vector<uint8_t> Sha256(const uint8_t* data, size_t len);

// Binary Merkle tree over sorted leaves; inclusion proofs.
class MerkleTree {
 public:
  void AddLeaf(const std::vector<uint8_t>& leaf_hash);
  void Rebuild(const std::vector<std::vector<uint8_t>>& leaf_hashes);
  std::vector<uint8_t> Root() const;
  // Proof: sibling hashes from leaf to root + leaf index.
  bool Proof(size_t index, std::vector<std::vector<uint8_t>>& siblings_out) const;
  static bool VerifyProof(const std::vector<uint8_t>& leaf,
                          const std::vector<std::vector<uint8_t>>& siblings, size_t index,
                          const std::vector<uint8_t>& expected_root);
  size_t LeafCount() const { return leaves_.size(); }

 private:
  std::vector<std::vector<uint8_t>> leaves_;
  std::vector<std::vector<std::vector<uint8_t>>> levels_;  // levels_[0] = leaves
  void BuildLevels();
};

// Versioned, signed revocation list; hot path reads via atomic shared_ptr swap.
struct RevocationList {
  uint64_t version = 0;
  std::vector<std::string> revoked;  // sorted
  std::vector<uint8_t> issuer_sig;   // over version||sorted ids (ed25519)
};

class RevocationStore {
 public:
  bool Load(const std::string& path, const std::vector<uint8_t>& issuer_pubkey, std::string& err);
  bool Save(const std::string& path, const RevocationList& list,
            const std::vector<uint8_t>& issuer_sig_extra, std::string& err);
  // Lock-free hot path.
  std::shared_ptr<RevocationList> Current() const;
  void Install(std::shared_ptr<RevocationList> list);
  bool IsRevoked(const std::string& ticket_id) const;
  // Verify envelope: version(u64be)||count(u32be)||ids..., sig by issuer.
  static bool Verify(const RevocationList& list, const std::vector<uint8_t>& issuer_pubkey);
  static std::vector<uint8_t> SignBytes(const RevocationList& list);

 private:
  mutable std::mutex mu_;
  std::shared_ptr<RevocationList> cur_ = std::make_shared<RevocationList>();
};

}  // namespace gatecrypt
