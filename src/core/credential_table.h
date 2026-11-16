#pragma once
// Sharded concurrent credential table with atomic CAS state machine.
//
// Design: 64 shards, each shard = mutex + unordered_map<ticket_id, shared_ptr<Entry>>.
// Per-entry state is atomic<CredState>; transitions VALID->USED and *->REVOKED
// via compare_exchange. Exactly-once under burst: concurrent double-scans race
// on the same atomic; exactly one CAS VALID->USED succeeds, others observe USED.
//
// ABA / reclamation: entries are never freed or reused in place. USED/REVOKED
// are terminal tombstones held by shared_ptr; readers hold a shared_ptr copy so
// no use-after-free. Re-issuance of the same ticket_id requires explicit
// Remove()+Insert() (new Entry object), so no ABA on the state atomic.
// Sharded mutexes chosen over a fully lock-free table for auditability and
// simpler correctness; per-entry CAS still gives lock-free fast path for the
// state transition itself.
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace gatecrypt {

enum class CredState : uint8_t { VALID = 0, USED = 1, REVOKED = 2 };

struct CredEntry {
  std::string ticket_id;
  std::vector<uint8_t> device_pubkey;  // 32 bytes bound at issuance
  std::vector<uint8_t> issuer_sig;     // issuer signature over ticket binding
  std::atomic<CredState> state{CredState::VALID};
};

class CredentialTable {
 public:
  explicit CredentialTable(size_t shards = 64);
  // Insert a fresh VALID credential. Returns false if ticket already exists.
  bool Insert(const std::string& ticket_id, const std::vector<uint8_t>& device_pubkey,
              const std::vector<uint8_t>& issuer_sig);
  std::shared_ptr<CredEntry> Find(const std::string& ticket_id);
  // Atomic VALID->USED. True iff this caller won the race.
  bool TryConsume(const std::shared_ptr<CredEntry>& e);
  bool Revoke(const std::string& ticket_id);
  // Used by WAL recovery to mark USED without racing (under shard lock).
  bool ApplyUsed(const std::string& ticket_id);
  bool ApplyRevoke(const std::string& ticket_id);
  size_t Size() const;
  void ForEachUsed(std::vector<std::string>& out) const;

 private:
  struct Shard {
    mutable std::mutex mu;
    std::unordered_map<std::string, std::shared_ptr<CredEntry>> map;
  };
  Shard& Pick(const std::string& id);
  const Shard& Pick(const std::string& id) const;
  std::vector<Shard> shards_;
};

}  // namespace gatecrypt
