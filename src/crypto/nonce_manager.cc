#include "crypto/nonce_manager.h"

#include <openssl/rand.h>

#include <chrono>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>

namespace gatecrypt {

struct NonceManagerImpl {
  std::mutex mu;
  std::unordered_map<std::string, NonceManager::Entry> map;
  std::deque<std::string> order;
};

int64_t NonceManager::NowMs() {
  using namespace std::chrono;
  return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

NonceManager::NonceManager(uint64_t ttl_ms, size_t capacity, int64_t skew_ms)
    : ttl_ms_(ttl_ms), capacity_(capacity), skew_ms_(skew_ms) {
  auto* impl = new NonceManagerImpl();
  mu_ = impl;
  // map_/order_ point into impl for ABI compat with header's void* fields
  map_ = impl;
  order_ = impl;
  (void)skew_ms_;
}

static NonceManagerImpl* Imp(void* p) { return static_cast<NonceManagerImpl*>(p); }

NonceManager::~NonceManager() { delete Imp(mu_); }

std::vector<uint8_t> NonceManager::Issue() {
  std::vector<uint8_t> n(16);
  RAND_bytes(n.data(), 16);
  auto* impl = Imp(mu_);
  std::string key((char*)n.data(), 16);
  int64_t now = NowMs();
  {
    std::lock_guard<std::mutex> lk(impl->mu);
    if (impl->map.size() >= capacity_) {
      // Evict oldest until under capacity.
      while (!impl->order.empty() && impl->map.size() >= capacity_) {
        std::string old = impl->order.front();
        impl->order.pop_front();
        impl->map.erase(old);
      }
    }
    Entry e;
    e.expires_mono_ms = now + (int64_t)ttl_ms_;
    e.seq = 0;
    impl->map[key] = e;
    impl->order.push_back(key);
  }
  return n;
}

bool NonceManager::Consume(const uint8_t* nonce, size_t len) {
  if (len != 16 || nonce == nullptr) return false;
  std::string key((const char*)nonce, len);
  auto* impl = Imp(mu_);
  int64_t now = NowMs();
  std::lock_guard<std::mutex> lk(impl->mu);
  auto it = impl->map.find(key);
  if (it == impl->map.end()) return false;
  if (now > it->second.expires_mono_ms) {
    impl->map.erase(it);
    return false;
  }
  impl->map.erase(it);
  return true;
}

void NonceManager::EvictExpired() {
  auto* impl = Imp(mu_);
  int64_t now = NowMs();
  std::lock_guard<std::mutex> lk(impl->mu);
  while (!impl->order.empty()) {
    auto it = impl->map.find(impl->order.front());
    if (it == impl->map.end()) {
      impl->order.pop_front();
      continue;
    }
    if (now <= it->second.expires_mono_ms) break;
    impl->map.erase(it);
    impl->order.pop_front();
  }
}

size_t NonceManager::Size() const {
  auto* impl = Imp(const_cast<void*>(mu_));
  std::lock_guard<std::mutex> lk(impl->mu);
  return impl->map.size();
}

}  // namespace gatecrypt
