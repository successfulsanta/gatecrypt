#pragma once
// Central configuration: file + env overrides, validated at startup.
#include <cstdint>
#include <string>

namespace gatecrypt {

enum class FsyncPolicy { EveryWrite = 0, GroupCommit = 1, Interval = 2 };

struct Config {
  uint16_t port = 8443;
  uint16_t metrics_port = 9090;
  int io_threads = 2;
  int workers = 4;
  size_t ring_capacity = 65536;  // must be power of two
  size_t max_frame_bytes = 64 * 1024;
  int max_connections = 4096;
  int max_conn_per_ip = 256;
  uint64_t idle_timeout_ms = 15000;
  uint64_t header_timeout_ms = 5000;
  double rate_per_sec = 5000.0;
  double rate_burst = 1000.0;
  uint64_t nonce_ttl_ms = 30000;
  size_t nonce_capacity = 65536;
  int64_t clock_skew_ms = 5000;
  std::string data_dir = "./data";
  uint64_t wal_segment_bytes = 64u * 1024u * 1024u;
  FsyncPolicy fsync_policy = FsyncPolicy::GroupCommit;
  uint64_t group_commit_ms = 10;
  bool allow_plain = false;  // plain TCP only behind explicit dev flag
  bool tls_enabled = false;
  std::string tls_cert;
  std::string tls_key;
  std::string tls_ca;
  bool tls_require_client_cert = false;
  std::string issuer_pubkey_hex;
  std::string run_user;  // drop privileges to this user (empty = no-op)
  std::string log_level = "info";

  static Config Defaults();
  bool Validate(std::string& err) const;
  bool LoadFile(const std::string& path, std::string& err);
  void LoadEnv();  // GATECRYPT_* overrides
};

FsyncPolicy ParseFsyncPolicy(const std::string& s, bool& ok);
std::string ToString(FsyncPolicy p);

}  // namespace gatecrypt
