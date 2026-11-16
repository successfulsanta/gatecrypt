#include "storage/sync.h"

#include <algorithm>
#include <cstring>

#include "crypto/key_store.h"

namespace gatecrypt {

std::vector<uint8_t> SyncEnvelopeBytes(const SyncEnvelope& e) {
  std::vector<uint8_t> b;
  auto put64 = [&](uint64_t v) {
    for (int i = 7; i >= 0; --i) b.push_back((uint8_t)(v >> (8 * i)));
  };
  put64(e.from_gate);
  put64(e.version);
  put64(e.checkpoint.seqno);
  put64(e.checkpoint.gate_id);
  put64(e.checkpoint.timestamp_ms);
  b.insert(b.end(), e.checkpoint.root.begin(), e.checkpoint.root.end());
  uint32_t n = (uint32_t)e.used_tickets.size();
  b.push_back((uint8_t)(n >> 24));
  b.push_back((uint8_t)(n >> 16));
  b.push_back((uint8_t)(n >> 8));
  b.push_back((uint8_t)n);
  for (auto& t : e.used_tickets) {
    b.push_back((uint8_t)t.size());
    b.insert(b.end(), t.begin(), t.end());
  }
  return b;
}

bool SignEnvelope(SyncEnvelope& e, const uint8_t* priv_seed32) {
  SoftwareKeyStore ks;
  std::vector<uint8_t> seed(priv_seed32, priv_seed32 + 32);
  if (!ks.LoadPrivate(seed)) return false;
  std::vector<uint8_t> b = SyncEnvelopeBytes(e);
  return ks.Sign(b.data(), b.size(), e.checkpoint.signature);
}

bool VerifyEnvelope(const SyncEnvelope& e, const uint8_t* issuer_pub32) {
  if (e.checkpoint.signature.size() != 64) return false;
  std::vector<uint8_t> b = SyncEnvelopeBytes(e);
  return Ed25519Verify(issuer_pub32, b.data(), b.size(), e.checkpoint.signature.data());
}

void MergeUsedSets(const std::vector<std::string>& local_used, uint64_t local_gate,
                   const std::vector<std::string>& remote_used, uint64_t remote_gate,
                   std::vector<std::string>& to_mark_used, std::vector<std::string>& lost) {
  // Union; conflict = same ticket on both with different gates -> lowest gate wins.
  // Both stay USED locally; `lost` flags local scans that lost for audit.
  to_mark_used.clear();
  lost.clear();
  // Since we only exchange used-sets (no per-ticket gate provenance per ticket
  // beyond the envelope gate), a ticket present in both sets with differing
  // gates is a conflict. Lowest gate wins; if local lost, flag it.
  for (auto& t : remote_used) to_mark_used.push_back(t);
  if (local_gate != remote_gate) {
    uint64_t winner = local_gate < remote_gate ? local_gate : remote_gate;
    if (winner != local_gate) {
      // Local lost every conflict ticket (present in both).
      for (auto& t : local_used) {
        if (std::binary_search(remote_used.begin(), remote_used.end(), t)) lost.push_back(t);
      }
    }
  }
}

}  // namespace gatecrypt
