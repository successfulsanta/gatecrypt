#include "core/verify_engine.h"

#include <chrono>

#include "crypto/key_store.h"
#include "observability/metrics.h"

namespace gatecrypt {

VerifyEngine::VerifyEngine(const Config& cfg, CredentialTable& table, NonceManager& nonces,
                           Wal& wal, std::function<std::shared_ptr<RevocationList>()> revocation)
    : cfg_(cfg), table_(table), nonces_(nonces), wal_(wal), revocation_(revocation) {}

VerifyOutcome VerifyEngine::Verify(const VerifyRequest& req) {
  auto t0 = std::chrono::steady_clock::now();
  VerifyOutcome out;
  Metrics::Instance().IncRequests();

  // 1. Nonce: single-use, time-bounded. Consume first to prevent replay races.
  if (!nonces_.Consume(req.nonce)) {
    out.code = VerifyCode::Replay;
    Metrics::Instance().IncRejected();
    auto t1 = std::chrono::steady_clock::now();
    out.latency_us =
        (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
    Metrics::Instance().ObserveLatencyUs(out.latency_us);
    return out;
  }

  // 2. Lookup credential.
  auto entry = table_.Find(req.ticket_id);
  if (!entry) {
    out.code = VerifyCode::UnknownTicket;
    Metrics::Instance().IncRejected();
    auto t1 = std::chrono::steady_clock::now();
    out.latency_us =
        (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
    Metrics::Instance().ObserveLatencyUs(out.latency_us);
    return out;
  }

  // 3. Revocation hot path (lock-free snapshot).
  if (revocation_) {
    auto rl = revocation_();
    if (rl) {
      // Binary search over sorted list.
      const auto& v = rl->revoked;
      size_t lo = 0, hi = v.size();
      bool found = false;
      while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (v[mid] == req.ticket_id) {
          found = true;
          break;
        } else if (v[mid] < req.ticket_id) {
          lo = mid + 1;
        } else {
          hi = mid;
        }
      }
      if (found) {
        out.code = VerifyCode::Revoked;
        Metrics::Instance().IncRejected();
        auto t1 = std::chrono::steady_clock::now();
        out.latency_us =
            (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
        Metrics::Instance().ObserveLatencyUs(out.latency_us);
        return out;
      }
      if (entry->state.load(std::memory_order_acquire) == CredState::REVOKED) {
        out.code = VerifyCode::Revoked;
        Metrics::Instance().IncRejected();
        auto t1 = std::chrono::steady_clock::now();
        out.latency_us =
            (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
        Metrics::Instance().ObserveLatencyUs(out.latency_us);
        return out;
      }
    }
  } else {
    if (entry->state.load(std::memory_order_acquire) == CredState::REVOKED) {
      out.code = VerifyCode::Revoked;
      Metrics::Instance().IncRejected();
      auto t1 = std::chrono::steady_clock::now();
      out.latency_us =
          (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
      Metrics::Instance().ObserveLatencyUs(out.latency_us);
      return out;
    }
  }

  // 4. Already-used fast path (before expensive verify).
  if (entry->state.load(std::memory_order_acquire) == CredState::USED) {
    out.code = VerifyCode::Used;
    Metrics::Instance().IncRejected();
    auto t1 = std::chrono::steady_clock::now();
    out.latency_us =
        (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
    Metrics::Instance().ObserveLatencyUs(out.latency_us);
    return out;
  }

  // 5. Device binding: presented pubkey must match issuance binding (constant-time).
  if (req.device_pubkey.size() != 32 || entry->device_pubkey.size() != 32 ||
      !ConstantTimeEqual(req.device_pubkey, entry->device_pubkey)) {
    out.code = VerifyCode::InvalidSig;
    Metrics::Instance().IncRejected();
    auto t1 = std::chrono::steady_clock::now();
    out.latency_us =
        (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
    Metrics::Instance().ObserveLatencyUs(out.latency_us);
    return out;
  }

  // 6. Ed25519 verify over (nonce || ticket_id || context).
  std::vector<uint8_t> msg =
      BuildSignedMessage(req.nonce.data(), req.nonce.size(), req.ticket_id, req.context);
  if (req.signature.size() != 64 ||
      !Ed25519Verify(entry->device_pubkey.data(), msg.data(), msg.size(), req.signature.data())) {
    out.code = VerifyCode::InvalidSig;
    Metrics::Instance().IncRejected();
    SecureWipe(msg.data(), msg.size());
    auto t1 = std::chrono::steady_clock::now();
    out.latency_us =
        (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
    Metrics::Instance().ObserveLatencyUs(out.latency_us);
    return out;
  }
  SecureWipe(msg.data(), msg.size());

  // 7. CAS VALID -> USED. Exactly one winner under burst.
  if (!table_.TryConsume(entry)) {
    CredState s = entry->state.load(std::memory_order_acquire);
    out.code = (s == CredState::REVOKED) ? VerifyCode::Revoked : VerifyCode::Used;
    Metrics::Instance().IncCasConflicts();
    Metrics::Instance().IncRejected();
    auto t1 = std::chrono::steady_clock::now();
    out.latency_us =
        (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
    Metrics::Instance().ObserveLatencyUs(out.latency_us);
    return out;
  }

  // 8. WAL append (durable-before-ack per policy).
  std::string err;
  uint64_t seq = 0;
  if (!wal_.Append(WalRecordType::USE, req.ticket_id, seq, err)) {
    // WAL failure: state is already USED in memory. Keep it USED (fail-closed)
    // so we never double-admit; operator must reconcile via sync/checkpoint.
    out.code = VerifyCode::Malformed;
    Metrics::Instance().IncRejected();
    auto t1 = std::chrono::steady_clock::now();
    out.latency_us =
        (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
    Metrics::Instance().ObserveLatencyUs(out.latency_us);
    return out;
  }
  out.wal_seqno = seq;
  if (cfg_.fsync_policy == FsyncPolicy::EveryWrite) {
    std::string ferr;
    wal_.Flush(ferr);  // best effort; failure does not un-consume
  }

  out.code = VerifyCode::Ok;
  Metrics::Instance().IncVerified();
  auto t1 = std::chrono::steady_clock::now();
  out.latency_us = (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
  Metrics::Instance().ObserveLatencyUs(out.latency_us);
  return out;
}

}  // namespace gatecrypt
