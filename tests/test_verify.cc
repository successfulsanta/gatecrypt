#include <gtest/gtest.h>

#include <chrono>
#include <cstdio>

#include "config/config.h"
#include "core/credential_table.h"
#include "core/verify_engine.h"
#include "crypto/key_store.h"
#include "crypto/nonce_manager.h"
#include "storage/merkle.h"
#include "storage/wal.h"

using namespace gatecrypt;

struct Harness {
  Config cfg = Config::Defaults();
  CredentialTable table{16};
  NonceManager nonces{60000, 65536, 5000};
  std::string dir;
  std::unique_ptr<Wal> wal;
  std::shared_ptr<RevocationList> rl = std::make_shared<RevocationList>();
  SoftwareKeyStore device;
  std::string err;

  Harness() {
    char t[] = "/tmp/gc-verify-test-wal-XXXXXX";
    if (mkdtemp(t))
      dir = t;
    else
      dir = "/tmp/gc-verify-fallback";
    wal = std::make_unique<Wal>(dir, 1 << 20);
    cfg.allow_plain = true;
    cfg.fsync_policy = FsyncPolicy::Interval;  // no fsync in hot path
    wal->Open(err);
    device.Generate();
  }
  VerifyEngine Engine() {
    auto rlcopy = rl;
    return VerifyEngine(cfg, table, nonces, *wal, [rlcopy]() { return rlcopy; });
  }
  VerifyRequest MakeReq(const std::string& tid, const std::string& ctx = "gate-a") {
    auto n = nonces.Issue();
    auto msg = BuildSignedMessage(n.data(), n.size(), tid, ctx);
    std::vector<uint8_t> sig;
    device.Sign(msg.data(), msg.size(), sig);
    VerifyRequest r;
    r.nonce = n;
    r.ticket_id = tid;
    r.device_pubkey = device.GetPublicKey();
    r.signature = sig;
    r.context = ctx;
    return r;
  }
};

TEST(Verify, HappyPath) {
  Harness h;
  auto eng = h.Engine();
  h.table.Insert("T1", h.device.GetPublicKey(), {});
  auto out = eng.Verify(h.MakeReq("T1"));
  EXPECT_EQ(out.code, VerifyCode::Ok) << (int)out.code;
  EXPECT_GT(out.wal_seqno, 0u);
}

TEST(Verify, DoubleScanExactlyOnce) {
  Harness h;
  auto eng = h.Engine();
  h.table.Insert("T2", h.device.GetPublicKey(), {});
  auto r1 = h.MakeReq("T2");
  EXPECT_EQ(eng.Verify(r1).code, VerifyCode::Ok);
  auto r2 = h.MakeReq("T2");
  EXPECT_EQ(eng.Verify(r2).code, VerifyCode::Used);
}

TEST(Verify, ReplayRejected) {
  Harness h;
  auto eng = h.Engine();
  h.table.Insert("T3", h.device.GetPublicKey(), {});
  auto r = h.MakeReq("T3");
  // Consume nonce out-of-band first -> engine sees replay.
  EXPECT_TRUE(h.nonces.Consume(r.nonce));
  // Re-issue path: craft request with already-consumed nonce.
  EXPECT_EQ(eng.Verify(r).code, VerifyCode::Replay);
}

TEST(Verify, BadSigRejected) {
  Harness h;
  auto eng = h.Engine();
  h.table.Insert("T4", h.device.GetPublicKey(), {});
  auto r = h.MakeReq("T4");
  r.signature[0] ^= 0xFF;
  EXPECT_EQ(eng.Verify(r).code, VerifyCode::InvalidSig);
}

TEST(Verify, WrongDeviceKeyRejected) {
  Harness h;
  auto eng = h.Engine();
  h.table.Insert("T5", h.device.GetPublicKey(), {});
  auto r = h.MakeReq("T5");
  SoftwareKeyStore attacker;
  attacker.Generate();
  r.device_pubkey = attacker.GetPublicKey();
  EXPECT_EQ(eng.Verify(r).code, VerifyCode::InvalidSig);
}

TEST(Verify, UnknownTicket) {
  Harness h;
  auto eng = h.Engine();
  EXPECT_EQ(eng.Verify(h.MakeReq("NOPE")).code, VerifyCode::UnknownTicket);
}

TEST(Verify, RevokedRejected) {
  Harness h;
  h.rl->revoked = {"T6"};
  auto eng = h.Engine();
  h.table.Insert("T6", h.device.GetPublicKey(), {});
  EXPECT_EQ(eng.Verify(h.MakeReq("T6")).code, VerifyCode::Revoked);
}

TEST(Verify, OfflineLatencyUnder3ms) {
  Harness h;
  auto eng = h.Engine();
  const int N = 2000;
  for (int i = 0; i < N; ++i) h.table.Insert("L-" + std::to_string(i), h.device.GetPublicKey(), {});
  uint64_t worst = 0;
  for (int i = 0; i < N; ++i) {
    auto o = eng.Verify(h.MakeReq("L-" + std::to_string(i)));
    EXPECT_EQ(o.code, VerifyCode::Ok);
    worst = std::max(worst, o.latency_us);
  }
  EXPECT_LT(worst, 3000u) << "offline p100 " << worst << "us exceeds 3ms budget";
}
