#pragma once
// Async TCP server: epoll edge-triggered, non-blocking, SO_REUSEPORT,
// TCP_NODELAY, per-IP token bucket, idle/slowloris timeouts, TLS optional.
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "config/config.h"

namespace gatecrypt {

struct ServerStats {
  uint64_t accepted = 0;
  uint64_t rejected_conn_limit = 0;
  uint64_t rate_limited = 0;
  uint64_t busy_responses = 0;
};

// Push-style: parsed VERIFY payloads delivered to workers.
using VerifyHandler = std::function<std::vector<uint8_t>(const std::vector<uint8_t>&)>;

class EpollServer {
 public:
  EpollServer(const Config& cfg, VerifyHandler handler);
  ~EpollServer();
  bool Start(std::string& err);
  void Stop();
  void Run();  // blocks; call on IO thread(s)
  ServerStats stats() const;

 private:
  const Config& cfg_;
  VerifyHandler handler_;
  struct Impl;
  Impl* impl_ = nullptr;
};

}  // namespace gatecrypt
