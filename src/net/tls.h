#pragma once
// Optional TLS/mTLS transport wrapper over OpenSSL. Plain TCP only behind
// explicit dev flag (allow_plain); fail-closed default.
#include <cstdint>
#include <string>
#include <vector>

namespace gatecrypt {

struct TlsConfig {
  bool enabled = false;
  std::string cert_file;
  std::string key_file;
  std::string ca_file;
  bool require_client_cert = false;
};

class TlsContext {
 public:
  explicit TlsContext(const TlsConfig& cfg);
  ~TlsContext();
  bool Init(std::string& err);
  bool IsEnabled() const { return enabled_; }
  // Wrap an accepted fd with server-side TLS handshake (blocking, short timeout).
  // Returns new SSL* handle as opaque pointer; nullptr on failure.
  void* Accept(int fd, std::string& err);
  int Read(void* ssl, uint8_t* buf, size_t n);
  int Write(void* ssl, const uint8_t* buf, size_t n);
  void Close(void* ssl, int fd);

 private:
  TlsConfig cfg_;
  bool enabled_ = false;
  void* ctx_ = nullptr;  // SSL_CTX*
};

}  // namespace gatecrypt
