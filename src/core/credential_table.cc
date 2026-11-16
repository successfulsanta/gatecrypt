#include "core/credential_table.h"

#include <functional>

namespace gatecrypt {

CredentialTable::CredentialTable(size_t shards) : shards_(shards ? shards : 64) {}

CredentialTable::Shard& CredentialTable::Pick(const std::string& id) {
  size_t h = std::hash<std::string>{}(id);
  return shards_[h % shards_.size()];
}

const CredentialTable::Shard& CredentialTable::Pick(const std::string& id) const {
  size_t h = std::hash<std::string>{}(id);
  return shards_[h % shards_.size()];
}

bool CredentialTable::Insert(const std::string& ticket_id,
                             const std::vector<uint8_t>& device_pubkey,
                             const std::vector<uint8_t>& issuer_sig) {
  if (ticket_id.empty()) return false;
  Shard& s = Pick(ticket_id);
  std::lock_guard<std::mutex> lk(s.mu);
  if (s.map.count(ticket_id)) return false;
  auto e = std::make_shared<CredEntry>();
  e->ticket_id = ticket_id;
  e->device_pubkey = device_pubkey;
  e->issuer_sig = issuer_sig;
  e->state.store(CredState::VALID, std::memory_order_relaxed);
  s.map[ticket_id] = e;
  return true;
}

std::shared_ptr<CredEntry> CredentialTable::Find(const std::string& ticket_id) {
  const Shard& s = Pick(ticket_id);
  std::lock_guard<std::mutex> lk(s.mu);
  auto it = s.map.find(ticket_id);
  if (it == s.map.end()) return nullptr;
  return it->second;
}

bool CredentialTable::TryConsume(const std::shared_ptr<CredEntry>& e) {
  if (!e) return false;
  CredState expect = CredState::VALID;
  return e->state.compare_exchange_strong(expect, CredState::USED, std::memory_order_acq_rel,
                                          std::memory_order_acquire);
}

bool CredentialTable::Revoke(const std::string& ticket_id) {
  auto e = Find(ticket_id);
  if (!e) return false;
  CredState cur = e->state.load(std::memory_order_acquire);
  while (cur != CredState::REVOKED) {
    if (e->state.compare_exchange_weak(cur, CredState::REVOKED, std::memory_order_acq_rel,
                                       std::memory_order_acquire))
      return true;
  }
  return false;
}

bool CredentialTable::ApplyUsed(const std::string& ticket_id) {
  auto e = Find(ticket_id);
  if (!e) return false;
  e->state.store(CredState::USED, std::memory_order_release);
  return true;
}

bool CredentialTable::ApplyRevoke(const std::string& ticket_id) {
  auto e = Find(ticket_id);
  if (!e) return false;
  e->state.store(CredState::REVOKED, std::memory_order_release);
  return true;
}

size_t CredentialTable::Size() const {
  size_t n = 0;
  for (auto& s : shards_) {
    std::lock_guard<std::mutex> lk(s.mu);
    n += s.map.size();
  }
  return n;
}

void CredentialTable::ForEachUsed(std::vector<std::string>& out) const {
  for (auto& s : shards_) {
    std::lock_guard<std::mutex> lk(s.mu);
    for (auto& kv : s.map) {
      if (kv.second->state.load(std::memory_order_acquire) == CredState::USED)
        out.push_back(kv.first);
    }
  }
}

}  // namespace gatecrypt
