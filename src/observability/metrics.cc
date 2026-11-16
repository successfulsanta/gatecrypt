#include "observability/metrics.h"

#include <algorithm>
#include <mutex>
#include <sstream>

namespace gatecrypt {

Metrics& Metrics::Instance() {
  static Metrics m;
  return m;
}

void Metrics::ObserveLatencyUs(uint64_t us) {
  std::lock_guard<std::mutex> lk(mu_);
  latencies_.push_back(us);
  if (latencies_.size() > 8192) latencies_.erase(latencies_.begin(), latencies_.begin() + 1024);
}

void Metrics::ObserveFsyncUs(uint64_t us) {
  std::lock_guard<std::mutex> lk(mu_);
  fsync_us_.push_back(us);
  if (fsync_us_.size() > 2048) fsync_us_.erase(fsync_us_.begin(), fsync_us_.begin() + 256);
}

void Metrics::LatencyQuantiles(double& p50, double& p99, double& p999) const {
  std::lock_guard<std::mutex> lk(mu_);
  if (latencies_.empty()) {
    p50 = p99 = p999 = 0;
    return;
  }
  std::vector<uint64_t> v = latencies_;
  std::sort(v.begin(), v.end());
  auto q = [&](double f) -> double {
    size_t i = (size_t)(f * (v.size() - 1));
    return (double)v[i];
  };
  p50 = q(0.50);
  p99 = q(0.99);
  p999 = q(0.999);
}

std::string Metrics::Render() const {
  double p50, p99, p999;
  LatencyQuantiles(p50, p99, p999);
  uint64_t favg = 0;
  {
    std::lock_guard<std::mutex> lk(mu_);
    if (!fsync_us_.empty()) {
      uint64_t s = 0;
      for (auto x : fsync_us_) s += x;
      favg = s / fsync_us_.size();
    }
  }
  std::ostringstream os;
  os << "# HELP gatecrypt_requests_total Total requests\n# TYPE gatecrypt_requests_total counter\n";
  os << "gatecrypt_requests_total " << requests_.load() << "\n";
  os << "gatecrypt_verified_total " << verified_.load() << "\n";
  os << "gatecrypt_rejected_total " << rejected_.load() << "\n";
  os << "gatecrypt_busy_total " << busy_.load() << "\n";
  os << "gatecrypt_cas_conflicts_total " << cas_conflicts_.load() << "\n";
  os << "gatecrypt_queue_depth " << queue_depth_.load() << "\n";
  os << "gatecrypt_latency_p50_us " << p50 << "\n";
  os << "gatecrypt_latency_p99_us " << p99 << "\n";
  os << "gatecrypt_latency_p999_us " << p999 << "\n";
  os << "gatecrypt_fsync_avg_us " << favg << "\n";
  return os.str();
}

}  // namespace gatecrypt
