#pragma once
// Offline-capable verification engine: nonce -> signature -> revocation ->
// CAS state -> WAL. Target < 3ms on commodity hardware (measured in benches).
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "config/config.h"
#include "core/credential_table.h"
#include "crypto/nonce_manager.h"
#include "protocol/framing.h"
#include "storage/merkle.h"
#include "storage/wal.h"

namespace gatecrypt {

struct VerifyOutcome {
  VerifyCode code = VerifyCode::Malformed;
  uint64_t latency_us = 0;
  uint64_t wal_seqno = 0;
};

class VerifyEngine {
 public:
  VerifyEngine(const Config& cfg, CredentialTable& table, NonceManager& nonces, Wal& wal,
               std::function<std::shared_ptr<RevocationList>()> revocation);
  // Full offline verify of one request. Durable-before-ack per fsync policy:
  // GroupCommit/Interval queue the record and Flush happens on schedule; the
  // caller (server) acks after Append returns; EveryWrite fsyncs inline.
  VerifyOutcome Verify(const VerifyRequest& req);

 private:
  const Config& cfg_;
  CredentialTable& table_;
  NonceManager& nonces_;
  Wal& wal_;
  std::function<std::shared_ptr<RevocationList>()> revocation_;
};

}  // namespace gatecrypt
