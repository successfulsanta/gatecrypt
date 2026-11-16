#include <algorithm>
#include <fstream>

#include "crypto/key_store.h"
#include "crypto/secure.h"
#include "storage/merkle.h"

namespace gatecrypt {

std::vector<uint8_t> RevocationStore::SignBytes(const RevocationList& list) {
  std::vector<uint8_t> b;
  for (int i = 7; i >= 0; --i) b.push_back((uint8_t)(list.version >> (8 * i)));
  uint32_t n = (uint32_t)list.revoked.size();
  b.push_back((uint8_t)(n >> 24));
  b.push_back((uint8_t)(n >> 16));
  b.push_back((uint8_t)(n >> 8));
  b.push_back((uint8_t)n);
  for (auto& id : list.revoked) {
    b.push_back((uint8_t)id.size());
    b.insert(b.end(), id.begin(), id.end());
  }
  return b;
}

bool RevocationStore::Verify(const RevocationList& list,
                             const std::vector<uint8_t>& issuer_pubkey) {
  if (issuer_pubkey.size() != 32 || list.issuer_sig.size() != 64) return false;
  std::vector<uint8_t> b = SignBytes(list);
  return Ed25519Verify(issuer_pubkey.data(), b.data(), b.size(), list.issuer_sig.data());
}

std::shared_ptr<RevocationList> RevocationStore::Current() const {
  std::lock_guard<std::mutex> lk(mu_);
  return cur_;
}

void RevocationStore::Install(std::shared_ptr<RevocationList> list) {
  std::lock_guard<std::mutex> lk(mu_);
  if (list && list->version >= cur_->version) cur_ = list;
}

bool RevocationStore::IsRevoked(const std::string& ticket_id) const {
  auto c = Current();
  return std::binary_search(c->revoked.begin(), c->revoked.end(), ticket_id);
}

bool RevocationStore::Load(const std::string& path, const std::vector<uint8_t>& issuer_pubkey,
                           std::string& err) {
  std::ifstream f(path, std::ios::binary);
  if (!f.good()) return true;  // absent = empty list (fresh install)
  uint64_t ver = 0;
  uint32_t n = 0;
  char hb[12];
  f.read(hb, 12);
  if ((size_t)f.gcount() != 12) {
    err = "short revocation header";
    return false;
  }
  for (int i = 0; i < 8; ++i) ver = (ver << 8) | (uint8_t)hb[i];
  n = ((uint32_t)(uint8_t)hb[8] << 24) | ((uint32_t)(uint8_t)hb[9] << 16) |
      ((uint32_t)(uint8_t)hb[10] << 8) | (uint8_t)hb[11];
  if (n > 1000000) {
    err = "revocation list too large";
    return false;
  }
  auto list = std::make_shared<RevocationList>();
  list->version = ver;
  for (uint32_t i = 0; i < n; ++i) {
    char lb[1];
    f.read(lb, 1);
    if (!f.good()) {
      err = "truncated revocation entry";
      return false;
    }
    size_t L = (uint8_t)lb[0];
    std::string id(L, '\0');
    if (L) {
      f.read(id.data(), (std::streamsize)L);
      if (!f.good()) {
        err = "truncated revocation id";
        return false;
      }
    }
    list->revoked.push_back(id);
  }
  char sig[64];
  f.read(sig, 64);
  if ((size_t)f.gcount() != 64) {
    err = "missing revocation signature";
    return false;
  }
  list->issuer_sig.assign(sig, sig + 64);
  std::sort(list->revoked.begin(), list->revoked.end());
  if (!issuer_pubkey.empty() && !Verify(*list, issuer_pubkey)) {
    err = "revocation signature invalid";
    return false;
  }
  Install(list);
  return true;
}

bool RevocationStore::Save(const std::string& path, const RevocationList& list,
                           const std::vector<uint8_t>&, std::string& err) {
  std::string tmp = path + ".tmp";
  std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
  if (!f.good()) {
    err = "cannot write revocation tmp";
    return false;
  }
  char hb[12];
  for (int i = 7; i >= 0; --i) hb[7 - i] = (char)(list.version >> (8 * i));
  uint32_t n = (uint32_t)list.revoked.size();
  hb[8] = (char)(n >> 24);
  hb[9] = (char)(n >> 16);
  hb[10] = (char)(n >> 8);
  hb[11] = (char)n;
  f.write(hb, 12);
  for (auto& id : list.revoked) {
    char L = (char)id.size();
    f.write(&L, 1);
    f.write(id.data(), (std::streamsize)id.size());
  }
  if (list.issuer_sig.size() != 64) {
    err = "revocation sig must be 64 bytes";
    return false;
  }
  f.write((const char*)list.issuer_sig.data(), 64);
  f.close();
  if (rename(tmp.c_str(), path.c_str()) != 0) {
    err = "rename revocation file";
    return false;
  }
  return true;
}

}  // namespace gatecrypt
