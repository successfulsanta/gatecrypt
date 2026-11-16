#pragma once
// Multi-device sync: signed WAL segment export/import + checkpoint exchange.
// Deterministic conflict resolution: for the same ticket scanned on two offline
// gates, lowest gate-ID wins; the loser is marked DUPLICATE (stays USED, the
// duplicate scan is rejected as replay). Checkpoints carry Merkle signed roots.
#include <cstdint>
#include <string>
#include <vector>

namespace gatecrypt {

struct Checkpoint {
  uint64_t seqno = 0;
  uint64_t gate_id = 0;
  uint64_t timestamp_ms = 0;
  std::vector<uint8_t> root;       // merkle root (32 bytes)
  std::vector<uint8_t> signature;  // issuer/device signature over envelope
};

struct SyncEnvelope {
  uint64_t from_gate = 0;
  uint64_t version = 1;
  std::vector<std::string> used_tickets;  // sorted unique
  Checkpoint checkpoint;
};

std::vector<uint8_t> SyncEnvelopeBytes(const SyncEnvelope& e);
bool SignEnvelope(SyncEnvelope& e, const uint8_t* priv_seed32);
bool VerifyEnvelope(const SyncEnvelope& e, const uint8_t* issuer_pub32);

// Merge remote used-set into local decision set.
// Returns tickets the local gate must mark USED (winner or already used).
// Conflict rule: if ticket appears in both local and remote with different
// gate winners, lowest gate_id wins; local scans that lost are flagged in
// `lost` (caller treats them as duplicates on audit).
void MergeUsedSets(const std::vector<std::string>& local_used, uint64_t local_gate,
                   const std::vector<std::string>& remote_used, uint64_t remote_gate,
                   std::vector<std::string>& to_mark_used, std::vector<std::string>& lost);

}  // namespace gatecrypt
