#include "config/config.h"

#include <cstdlib>
#include <fstream>
#include <sstream>

namespace gatecrypt {

Config Config::Defaults() { return Config{}; }

static bool IsPow2(size_t v) { return v && ((v & (v - 1)) == 0); }

bool Config::Validate(std::string& err) const {
  if (port == 0) {
    err = "port must be non-zero";
    return false;
  }
  if (metrics_port == port) {
    err = "metrics_port must differ from port";
    return false;
  }
  if (!IsPow2(ring_capacity)) {
    err = "ring_capacity must be power of two";
    return false;
  }
  if (max_frame_bytes == 0 || max_frame_bytes > 16 * 1024 * 1024) {
    err = "max_frame_bytes out of range";
    return false;
  }
  if (max_connections <= 0 || max_connections > 100000) {
    err = "max_connections out of range";
    return false;
  }
  if (nonce_ttl_ms == 0) {
    err = "nonce_ttl_ms must be non-zero";
    return false;
  }
  if (!tls_enabled && !allow_plain) {
    err = "plain TCP requires allow_plain=true (explicit dev flag)";
    return false;
  }
  if (tls_enabled && (tls_cert.empty() || tls_key.empty())) {
    err = "tls_enabled requires tls_cert and tls_key";
    return false;
  }
  return true;
}

static inline std::string Trim(const std::string& s) {
  size_t a = s.find_first_not_of(" \t\r\n");
  if (a == std::string::npos) return "";
  size_t b = s.find_last_not_of(" \t\r\n");
  return s.substr(a, b - a + 1);
}

bool Config::LoadFile(const std::string& path, std::string& err) {
  std::ifstream f(path);
  if (!f.good()) {
    err = "cannot open config file: " + path;
    return false;
  }
  std::string line;
  auto setKv = [&](const std::string& k, const std::string& v) -> bool {
    try {
      if (k == "port")
        port = static_cast<uint16_t>(std::stoi(v));
      else if (k == "metrics_port")
        metrics_port = static_cast<uint16_t>(std::stoi(v));
      else if (k == "io_threads")
        io_threads = std::stoi(v);
      else if (k == "workers")
        workers = std::stoi(v);
      else if (k == "ring_capacity")
        ring_capacity = static_cast<size_t>(std::stoul(v));
      else if (k == "max_frame_bytes")
        max_frame_bytes = static_cast<size_t>(std::stoul(v));
      else if (k == "max_connections")
        max_connections = std::stoi(v);
      else if (k == "max_conn_per_ip")
        max_conn_per_ip = std::stoi(v);
      else if (k == "idle_timeout_ms")
        idle_timeout_ms = std::stoull(v);
      else if (k == "header_timeout_ms")
        header_timeout_ms = std::stoull(v);
      else if (k == "rate_per_sec")
        rate_per_sec = std::stod(v);
      else if (k == "rate_burst")
        rate_burst = std::stod(v);
      else if (k == "nonce_ttl_ms")
        nonce_ttl_ms = std::stoull(v);
      else if (k == "nonce_capacity")
        nonce_capacity = static_cast<size_t>(std::stoul(v));
      else if (k == "clock_skew_ms")
        clock_skew_ms = std::stoll(v);
      else if (k == "data_dir")
        data_dir = v;
      else if (k == "wal_segment_bytes")
        wal_segment_bytes = std::stoull(v);
      else if (k == "fsync_policy") {
        bool ok = false;
        fsync_policy = ParseFsyncPolicy(v, ok);
        if (!ok) {
          err = "bad fsync_policy: " + v;
          return false;
        }
      } else if (k == "group_commit_ms")
        group_commit_ms = std::stoull(v);
      else if (k == "allow_plain")
        allow_plain = (v == "1" || v == "true" || v == "yes");
      else if (k == "tls_enabled")
        tls_enabled = (v == "1" || v == "true" || v == "yes");
      else if (k == "tls_cert")
        tls_cert = v;
      else if (k == "tls_key")
        tls_key = v;
      else if (k == "tls_ca")
        tls_ca = v;
      else if (k == "tls_require_client_cert")
        tls_require_client_cert = (v == "1" || v == "true" || v == "yes");
      else if (k == "issuer_pubkey_hex")
        issuer_pubkey_hex = v;
      else if (k == "run_user")
        run_user = v;
      else if (k == "log_level")
        log_level = v;
    } catch (...) {
      err = "bad value for " + k + ": " + v;
      return false;
    }
    return true;
  };
  while (std::getline(f, line)) {
    line = Trim(line);
    if (line.empty() || line[0] == '#') continue;
    auto pos = line.find('=');
    if (pos == std::string::npos) continue;
    std::string k = Trim(line.substr(0, pos));
    std::string v = Trim(line.substr(pos + 1));
    if (!setKv(k, v)) return false;
  }
  return true;
}

static const char* GetEnv(const char* n) {
  const char* v = std::getenv(n);
  return v ? v : nullptr;
}

void Config::LoadEnv() {
  std::string err;
  auto apply = [&](const char* env, auto& field, auto parse) {
    if (const char* v = GetEnv(env)) {
      try {
        field = parse(std::string(v));
      } catch (...) {
      }
    }
  };
  if (const char* v = GetEnv("GATECRYPT_PORT")) port = static_cast<uint16_t>(std::stoi(v));
  if (const char* v = GetEnv("GATECRYPT_METRICS_PORT"))
    metrics_port = static_cast<uint16_t>(std::stoi(v));
  if (const char* v = GetEnv("GATECRYPT_IO_THREADS")) io_threads = std::stoi(v);
  if (const char* v = GetEnv("GATECRYPT_WORKERS")) workers = std::stoi(v);
  if (const char* v = GetEnv("GATECRYPT_RING_CAPACITY"))
    ring_capacity = static_cast<size_t>(std::stoul(v));
  if (const char* v = GetEnv("GATECRYPT_DATA_DIR")) data_dir = v;
  if (const char* v = GetEnv("GATECRYPT_ALLOW_PLAIN"))
    allow_plain = (std::string(v) == "1" || std::string(v) == "true");
  if (const char* v = GetEnv("GATECRYPT_TLS_ENABLED"))
    tls_enabled = (std::string(v) == "1" || std::string(v) == "true");
  if (const char* v = GetEnv("GATECRYPT_TLS_CERT")) tls_cert = v;
  if (const char* v = GetEnv("GATECRYPT_TLS_KEY")) tls_key = v;
  if (const char* v = GetEnv("GATECRYPT_LOG_LEVEL")) log_level = v;
  if (const char* v = GetEnv("GATECRYPT_FSYNC_POLICY")) {
    bool ok = false;
    FsyncPolicy p = ParseFsyncPolicy(v, ok);
    if (ok) fsync_policy = p;
  }
  (void)apply;
  (void)err;
}

FsyncPolicy ParseFsyncPolicy(const std::string& s, bool& ok) {
  ok = true;
  if (s == "every_write" || s == "every-write" || s == "0") return FsyncPolicy::EveryWrite;
  if (s == "group_commit" || s == "group-commit" || s == "1") return FsyncPolicy::GroupCommit;
  if (s == "interval" || s == "2") return FsyncPolicy::Interval;
  ok = false;
  return FsyncPolicy::GroupCommit;
}

std::string ToString(FsyncPolicy p) {
  switch (p) {
    case FsyncPolicy::EveryWrite:
      return "every_write";
    case FsyncPolicy::GroupCommit:
      return "group_commit";
    case FsyncPolicy::Interval:
      return "interval";
  }
  return "group_commit";
}

}  // namespace gatecrypt
