#pragma once
#include <atomic>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace gatecrypt {

// Lock-free counters + latency histogram (microseconds).
class Metrics {
 public:
  static Metrics& Instance();

  void IncRequests() { requests_.fetch_add(1, std::memory_order_relaxed); }
  void IncVerified() { verified_.fetch_add(1, std::memory_order_relaxed); }
  void IncRejected() { rejected_.fetch_add(1, std::memory_order_relaxed); }
  void IncBusy() { busy_.fetch_add(1, std::memory_order_relaxed); }
  void IncCasConflicts() { cas_conflicts_.fetch_add(1, std::memory_order_relaxed); }
  void SetQueueDepth(uint64_t v) { queue_depth_.store(v, std::memory_order_relaxed); }
  void ObserveLatencyUs(uint64_t us);
  void ObserveFsyncUs(uint64_t us);

  uint64_t requests() const { return requests_.load(std::memory_order_relaxed); }

  // Prometheus text exposition.
  std::string Render() const;
  // p50/p99/p99.9 over observed latencies (approx, protected by mutex).
  void LatencyQuantiles(double& p50, double& p99, double& p999) const;

 private:
  Metrics() = default;
  std::atomic<uint64_t> requests_{0};
  std::atomic<uint64_t> verified_{0};
  std::atomic<uint64_t> rejected_{0};
  std::atomic<uint64_t> busy_{0};
  std::atomic<uint64_t> cas_conflicts_{0};
  std::atomic<uint64_t> queue_depth_{0};
  mutable std::mutex mu_;
  std::vector<uint64_t> latencies_;
  std::vector<uint64_t> fsync_us_;
};

}  // namespace gatecrypt
