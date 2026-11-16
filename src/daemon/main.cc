#include <atomic>
#include <chrono>
#include <csignal>
#include <cstring>
#include <iostream>
#include <memory>
#include <thread>
#include <vector>

#include "core/credential_table.h"
#include "core/ring_buffer.h"
#include "core/verify_engine.h"
#include "crypto/nonce_manager.h"
#include "net/epoll_server.h"
#include "observability/logger.h"
#include "observability/metrics.h"
#include "observability/metrics_server.h"
#include "protocol/framing.h"
#include "storage/merkle.h"
#include "storage/wal.h"

namespace {
std::atomic<bool> g_stop{false};
void OnSignal(int) { g_stop.store(true); }
}  // namespace

int main(int argc, char** argv) {
  using namespace gatecrypt;
  Config cfg = Config::Defaults();
  std::string cfg_path;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if ((a == "-c" || a == "--config") && i + 1 < argc)
      cfg_path = argv[++i];
    else if (a == "--allow-plain")
      cfg.allow_plain = true;
    else if (a == "--port" && i + 1 < argc)
      cfg.port = (uint16_t)std::stoi(argv[++i]);
  }
  if (!cfg_path.empty()) {
    std::string err;
    if (!cfg.LoadFile(cfg_path, err)) {
      std::cerr << "config error: " << err << "\n";
      return 1;
    }
  }
  cfg.LoadEnv();
  std::string err;
  if (!cfg.Validate(err)) {
    std::cerr << "invalid config: " << err << "\n";
    return 1;
  }
  SetLogLevelFromString(cfg.log_level);

  std::signal(SIGTERM, OnSignal);
  std::signal(SIGINT, OnSignal);

  CredentialTable table(64);
  NonceManager nonces(cfg.nonce_ttl_ms, cfg.nonce_capacity, cfg.clock_skew_ms);
  Wal wal(cfg.data_dir + "/wal", cfg.wal_segment_bytes);
  if (!wal.Open(err)) {
    std::cerr << "wal open: " << err << "\n";
    return 1;
  }
  // Replay: rebuild USED set.
  if (!wal.Replay(
          [&](const WalRecord& r) {
            std::string tid(r.payload.begin(), r.payload.end());
            if (r.type == WalRecordType::USE) {
              auto e = table.Find(tid);
              if (!e) {
                table.Insert(tid, std::vector<uint8_t>(32, 0), {});
              }
              table.ApplyUsed(tid);
            } else if (r.type == WalRecordType::REVOKE) {
              table.ApplyRevoke(tid);
            } else if (r.type == WalRecordType::ISSUE) {
              if (!table.Find(tid)) table.Insert(tid, std::vector<uint8_t>(32, 0), {});
            }
            return true;
          },
          err)) {
    std::cerr << "wal replay: " << err << "\n";
    return 1;
  }

  auto revocation = std::make_shared<RevocationList>();
  std::function<std::shared_ptr<RevocationList>()> rev_view = [revocation]() { return revocation; };

  VerifyEngine engine(cfg, table, nonces, wal, rev_view);
  std::mutex engine_mu;  // VerifyEngine::Verify mutates nonce table; serialize.

  VerifyHandler handler = [&](const std::vector<uint8_t>& payload) -> std::vector<uint8_t> {
    // Empty payload on NonceReq path: issue nonce.
    if (payload.empty()) {
      auto n = nonces.Issue();
      return EncodeFrame(MsgType::NonceResp, n.data(), n.size());
    }
    VerifyRequest req;
    std::string perr;
    if (!DecodeVerifyRequest(payload.data(), payload.size(), req, perr)) {
      return EncodeFrame(MsgType::Error, EncodeVerifyResponse(VerifyCode::Malformed));
    }
    VerifyOutcome o;
    {
      std::lock_guard<std::mutex> lk(engine_mu);
      o = engine.Verify(req);
    }
    if (o.code == VerifyCode::Busy) Metrics::Instance().IncBusy();
    auto body = EncodeVerifyResponse(o.code);
    if (o.code == VerifyCode::Ok) return EncodeFrame(MsgType::VerifyResp, body.data(), body.size());
    return EncodeFrame(MsgType::Error, body.data(), body.size());
  };

  EpollServer server(cfg, handler);
  if (!server.Start(err)) {
    std::cerr << "server start: " << err << "\n";
    return 1;
  }
  MetricsServer metrics(
      cfg.metrics_port, [] { return Metrics::Instance().Render(); }, [] { return !g_stop.load(); });
  std::string merr;
  if (!metrics.Start(merr)) {
    GC_LOG_WARN("metrics", std::string("metrics server: ") + merr);
  }
  if (!cfg.run_user.empty()) {
    if (!DropPrivileges(cfg.run_user, err)) {
      std::cerr << "privilege drop: " << err << "\n";
      return 1;
    }
    GC_LOG_INFO("daemon", "dropped privileges");
  }
  GC_LOG_INFO("daemon", "gatecryptd started");

  // Group-commit flusher.
  std::thread flusher([&] {
    using namespace std::chrono;
    while (!g_stop.load()) {
      std::this_thread::sleep_for(milliseconds(cfg.group_commit_ms));
      if (cfg.fsync_policy != FsyncPolicy::EveryWrite) {
        std::string ferr;
        wal.Flush(ferr);
      }
    }
  });

  while (!g_stop.load()) std::this_thread::sleep_for(std::chrono::milliseconds(50));

  GC_LOG_INFO("daemon", "draining; flushing WAL");
  metrics.Stop();
  server.Stop();
  {
    std::string ferr;
    wal.Flush(ferr);
  }
  // Final checkpoint marker.
  {
    uint64_t seq = 0;
    wal.Append(WalRecordType::CHECKPOINT, "shutdown", seq, err);
    wal.Flush(err);
  }
  if (flusher.joinable()) flusher.join();
  GC_LOG_INFO("daemon", "shutdown complete");
  return 0;
}
