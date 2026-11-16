#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cstring>

#include "crypto/key_store.h"
#include "crypto/secure.h"

namespace gatecrypt {

struct SoftwareKeyStore::Impl {
  EVP_PKEY* key = nullptr;
  std::vector<uint8_t> pubkey;  // 32 bytes
  ~Impl() {
    if (key) EVP_PKEY_free(key);
    pubkey.clear();
  }
};

SoftwareKeyStore::SoftwareKeyStore() : impl_(new Impl()) {}
SoftwareKeyStore::~SoftwareKeyStore() { delete impl_; }

bool SoftwareKeyStore::Generate() {
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
  if (!ctx) return false;
  EVP_PKEY* pkey = nullptr;
  bool ok = false;
  if (EVP_PKEY_keygen_init(ctx) == 1 && EVP_PKEY_keygen(ctx, &pkey) == 1) {
    size_t len = 32;
    std::vector<uint8_t> pub(32);
    if (EVP_PKEY_get_raw_public_key(pkey, pub.data(), &len) == 1 && len == 32) {
      if (impl_->key) EVP_PKEY_free(impl_->key);
      impl_->key = pkey;
      impl_->pubkey = pub;
      ok = true;
    } else {
      EVP_PKEY_free(pkey);
    }
  }
  EVP_PKEY_CTX_free(ctx);
  return ok;
}

bool SoftwareKeyStore::LoadPrivate(const std::vector<uint8_t>& seed_or_der) {
  EVP_PKEY* pkey = nullptr;
  if (seed_or_der.size() == 32) {
    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed_or_der.data(), 32);
  } else {
    const uint8_t* p = seed_or_der.data();
    pkey = d2i_PrivateKey(EVP_PKEY_ED25519, nullptr, &p, (long)seed_or_der.size());
  }
  if (!pkey) return false;
  size_t len = 32;
  std::vector<uint8_t> pub(32);
  if (EVP_PKEY_get_raw_public_key(pkey, pub.data(), &len) != 1 || len != 32) {
    EVP_PKEY_free(pkey);
    return false;
  }
  if (impl_->key) EVP_PKEY_free(impl_->key);
  impl_->key = pkey;
  impl_->pubkey = pub;
  return true;
}

std::vector<uint8_t> SoftwareKeyStore::GetPublicKey() const { return impl_->pubkey; }

bool SoftwareKeyStore::Sign(const uint8_t* msg, size_t len, std::vector<uint8_t>& sig_out) const {
  if (!impl_->key) return false;
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) return false;
  bool ok = false;
  size_t siglen = 64;
  sig_out.resize(64);
  if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, impl_->key) == 1 &&
      EVP_DigestSign(ctx, sig_out.data(), &siglen, msg, len) == 1 && siglen == 64) {
    ok = true;
  }
  EVP_MD_CTX_free(ctx);
  if (!ok) {
    SecureWipe(sig_out.data(), sig_out.size());
    sig_out.clear();
  }
  return ok;
}

void SoftwareKeyStore::Clear() {
  if (impl_->key) {
    EVP_PKEY_free(impl_->key);
    impl_->key = nullptr;
  }
  SecureWipe(impl_->pubkey.data(), impl_->pubkey.size());
  impl_->pubkey.clear();
}

bool Ed25519Verify(const uint8_t* pubkey32, const uint8_t* msg, size_t msglen,
                   const uint8_t* sig64) {
  if (!pubkey32 || !sig64 || (!msg && msglen)) return false;
  EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pubkey32, 32);
  if (!pkey) return false;
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  bool ok = false;
  if (ctx) {
    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1 &&
        EVP_DigestVerify(ctx, sig64, 64, msg, msglen) == 1) {
      ok = true;
    }
    EVP_MD_CTX_free(ctx);
  }
  EVP_PKEY_free(pkey);
  return ok;
}

static int HexVal(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

std::string HexEncode(const uint8_t* data, size_t n) {
  static const char* k = "0123456789abcdef";
  std::string s;
  s.reserve(n * 2);
  for (size_t i = 0; i < n; ++i) {
    s.push_back(k[data[i] >> 4]);
    s.push_back(k[data[i] & 15]);
  }
  return s;
}

bool HexDecode(const std::string& hex, std::vector<uint8_t>& out) {
  if (hex.size() % 2) return false;
  out.clear();
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    int hi = HexVal(hex[i]), lo = HexVal(hex[i + 1]);
    if (hi < 0 || lo < 0) return false;
    out.push_back((uint8_t)((hi << 4) | lo));
  }
  return true;
}

}  // namespace gatecrypt
