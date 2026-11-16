#pragma once
// Bounded single-use nonce manager with monotonic expiry.
#include <cstdint>
#include <string>
#include <vector>

namespace gatecrypt {

class NonceManager {
 public:
  explicit NonceManager(uint64_t ttl_ms = 30000, size_t capacity = 65536, int64_t skew_ms = 5000);
  ~NonceManager();
  NonceManager(const NonceManager&) = delete;
  NonceManager& operator=(const NonceManager&) = delete;
  // Issues a fresh 16-byte nonce.
  std::vector<uint8_t> Issue();
  // Consumes nonce; returns false on unknown/expired/replayed.
  bool Consume(const uint8_t* nonce, size_t len);
  bool Consume(const std::vector<uint8_t>& n) { return Consume(n.data(), n.size()); }
  void EvictExpired();
  size_t Size() const;

 public:
  struct Entry {
    int64_t expires_mono_ms;
    uint64_t seq;
  };

 private:
  uint64_t ttl_ms_;
  size_t capacity_;
  int64_t skew_ms_;
  mutable void* mu_ = nullptr;  // opaque to keep header light (actually std::mutex*)
  void* map_ = nullptr;         // unordered_map<string,Entry>*
  void* order_ = nullptr;       // deque<string>*
  static int64_t NowMs();
};

}  // namespace gatecrypt
