#include "crypto/secure.h"

#include <openssl/crypto.h>

namespace gatecrypt {

void SecureWipe(void* ptr, size_t n) {
  if (ptr == nullptr || n == 0) return;
  OPENSSL_cleanse(ptr, n);
}

bool ConstantTimeEqual(const uint8_t* a, const uint8_t* b, size_t n) {
  if (n == 0) return true;
  if (a == nullptr || b == nullptr) return false;
  return CRYPTO_memcmp(a, b, n) == 0;
}

bool ConstantTimeEqual(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
  if (a.size() != b.size()) return false;
  if (a.empty()) return true;
  return ConstantTimeEqual(a.data(), b.data(), a.size());
}

}  // namespace gatecrypt
