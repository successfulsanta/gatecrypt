#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "crypto/secure.h"

namespace gatecrypt {

class KeyStore {
 public:
  virtual ~KeyStore() = default;
  virtual bool Generate() = 0;
  virtual bool LoadPrivate(const std::vector<uint8_t>& seed_or_der) = 0;
  virtual std::vector<uint8_t> GetPublicKey() const = 0;
  virtual bool Sign(const uint8_t* msg, size_t len, std::vector<uint8_t>& sig_out) const = 0;
  virtual std::string BackendName() const = 0;
};

class SoftwareKeyStore : public KeyStore {
 public:
  SoftwareKeyStore();
  ~SoftwareKeyStore() override;
  bool Generate() override;
  bool LoadPrivate(const std::vector<uint8_t>& seed_or_der) override;
  std::vector<uint8_t> GetPublicKey() const override;
  bool Sign(const uint8_t* msg, size_t len, std::vector<uint8_t>& sig_out) const override;
  std::string BackendName() const override { return "software-fallback(dev/testing-only)"; }
  void Clear();

 private:
  struct Impl;
  Impl* impl_ = nullptr;
};

// Clearly labelled stubs: return false / unavailable.
class TpmKeyStore : public KeyStore {
 public:
  bool Generate() override { return false; }
  bool LoadPrivate(const std::vector<uint8_t>&) override { return false; }
  std::vector<uint8_t> GetPublicKey() const override { return {}; }
  bool Sign(const uint8_t*, size_t, std::vector<uint8_t>&) const override { return false; }
  std::string BackendName() const override { return "tpm2(unavailable)"; }
};

class Pkcs11KeyStore : public KeyStore {
 public:
  bool Generate() override { return false; }
  bool LoadPrivate(const std::vector<uint8_t>&) override { return false; }
  std::vector<uint8_t> GetPublicKey() const override { return {}; }
  bool Sign(const uint8_t*, size_t, std::vector<uint8_t>&) const override { return false; }
  std::string BackendName() const override { return "pkcs11(unavailable)"; }
};

bool Ed25519Verify(const uint8_t* pubkey32, const uint8_t* msg, size_t msglen,
                   const uint8_t* sig64);

std::string HexEncode(const uint8_t* data, size_t n);
bool HexDecode(const std::string& hex, std::vector<uint8_t>& out);

}  // namespace gatecrypt
