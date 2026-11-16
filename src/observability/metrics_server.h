#pragma once
// Minimal HTTP server for /metrics (Prometheus text) + /healthz + /readyz.
// Runs on metrics_port in its own thread; scrape-safe via lock-free counters.
#include <atomic>
#include <cstdint>
#include <functional>
#include <string>

namespace gatecrypt {

class MetricsServer {
 public:
  MetricsServer(uint16_t port, std::function<std::string()> render, std::function<bool()> ready);
  ~MetricsServer();
  bool Start(std::string& err);
  void Stop();

 private:
  uint16_t port_;
  std::function<std::string()> render_;
  std::function<bool()> ready_;
  struct Impl;
  Impl* impl_ = nullptr;
};

bool DropPrivileges(const std::string& user, std::string& err);

}  // namespace gatecrypt
