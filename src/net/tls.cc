#include "net/tls.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

namespace gatecrypt {

TlsContext::TlsContext(const TlsConfig& cfg) : cfg_(cfg), enabled_(cfg.enabled) {}
TlsContext::~TlsContext() {
  if (ctx_) SSL_CTX_free((SSL_CTX*)ctx_);
}

bool TlsContext::Init(std::string& err) {
  if (!enabled_) return true;
  if (cfg_.cert_file.empty() || cfg_.key_file.empty()) {
    err = "tls requires cert and key files";
    return false;
  }
  SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
  if (!ctx) {
    err = "SSL_CTX_new failed";
    return false;
  }
  if (SSL_CTX_use_certificate_file(ctx, cfg_.cert_file.c_str(), SSL_FILETYPE_PEM) != 1) {
    err = "bad tls cert: " + cfg_.cert_file;
    SSL_CTX_free(ctx);
    return false;
  }
  if (SSL_CTX_use_PrivateKey_file(ctx, cfg_.key_file.c_str(), SSL_FILETYPE_PEM) != 1) {
    err = "bad tls key: " + cfg_.key_file;
    SSL_CTX_free(ctx);
    return false;
  }
  if (!cfg_.ca_file.empty()) {
    if (SSL_CTX_load_verify_locations(ctx, cfg_.ca_file.c_str(), nullptr) != 1) {
      err = "bad tls ca: " + cfg_.ca_file;
      SSL_CTX_free(ctx);
      return false;
    }
  }
  if (cfg_.require_client_cert)
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
  else
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
  ctx_ = ctx;
  return true;
}

void* TlsContext::Accept(int fd, std::string& err) {
  if (!enabled_) return nullptr;
  SSL* ssl = SSL_new((SSL_CTX*)ctx_);
  if (!ssl) {
    err = "SSL_new failed";
    return nullptr;
  }
  SSL_set_fd(ssl, fd);
  if (SSL_accept(ssl) != 1) {
    err = "TLS handshake failed";
    SSL_free(ssl);
    return nullptr;
  }
  return ssl;
}

int TlsContext::Read(void* s, uint8_t* buf, size_t n) { return SSL_read((SSL*)s, buf, (int)n); }

int TlsContext::Write(void* s, const uint8_t* buf, size_t n) {
  return SSL_write((SSL*)s, buf, (int)n);
}

void TlsContext::Close(void* s, int) {
  if (s) {
    SSL_shutdown((SSL*)s);
    SSL_free((SSL*)s);
  }
}

}  // namespace gatecrypt
