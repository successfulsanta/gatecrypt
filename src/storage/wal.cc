#include "storage/wal.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>

#include "observability/logger.h"
#include "observability/metrics.h"
#include "storage/crc32c.h"

namespace gatecrypt {
namespace {

constexpr uint32_t kWalMagic = 0x57414C31u;  // 'WAL1'
constexpr size_t kHeaderLen = 4 + 8 + 2 + 4;
constexpr size_t kMaxPayload = 16u * 1024u * 1024u;

void PutU16LE(std::vector<uint8_t>& o, uint16_t v) {
  o.push_back(static_cast<uint8_t>(v));
  o.push_back(static_cast<uint8_t>(v >> 8));
}
void PutU32LE(std::vector<uint8_t>& o, uint32_t v) {
  for (int i = 0; i < 4; ++i) o.push_back(static_cast<uint8_t>(v >> (8 * i)));
}
void PutU64LE(std::vector<uint8_t>& o, uint64_t v) {
  for (int i = 0; i < 8; ++i) o.push_back(static_cast<uint8_t>(v >> (8 * i)));
}
uint16_t GetU16LE(const uint8_t* p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }
uint32_t GetU32LE(const uint8_t* p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
uint64_t GetU64LE(const uint8_t* p) {
  uint64_t v = 0;
  for (int i = 0; i < 8; ++i) v |= (uint64_t)p[i] << (8 * i);
  return v;
}

bool WriteFull(int fd, const uint8_t* buf, size_t n) {
  size_t off = 0;
  while (off < n) {
    ssize_t w = write(fd, buf + off, n - off);
    if (w < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    off += static_cast<size_t>(w);
  }
  return true;
}

// Read exactly n bytes at offset; sets eof=true if 0 bytes available at start.
bool PReadFull(int fd, uint64_t off, uint8_t* buf, size_t n, bool& eof) {
  size_t got = 0;
  while (got < n) {
    ssize_t r = pread(fd, buf + got, n - got, static_cast<off_t>(off + got));
    if (r < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    if (r == 0) {
      eof = (got == 0);
      return got > 0 ? false : true;  // short read mid-record => torn
    }
    got += static_cast<size_t>(r);
  }
  eof = false;
  return true;
}

}  // namespace

Wal::Wal(const std::string& dir, uint64_t segment_bytes)
    : dir_(dir), segment_bytes_(segment_bytes) {}

Wal::~Wal() { Close(); }

void Wal::Close() {
  if (fd_ >= 0) {
    close(fd_);
    fd_ = -1;
  }
}

std::string Wal::SegPath(uint64_t idx) const {
  char b[64];
  snprintf(b, sizeof(b), "seg-%06llu.wal", (unsigned long long)idx);
  return dir_ + "/" + b;
}

bool Wal::ListSegments(std::vector<uint64_t>& out) const {
  out.clear();
  DIR* d = opendir(dir_.c_str());
  if (!d) return false;
  while (dirent* e = readdir(d)) {
    unsigned long long idx = 0;
    if (sscanf(e->d_name, "seg-%06llu.wal", &idx) == 1) out.push_back(idx);
  }
  closedir(d);
  std::sort(out.begin(), out.end());
  return true;
}

bool Wal::OpenSegment(uint64_t idx, std::string& err) {
  Close();
  std::string p = SegPath(idx);
  fd_ = open(p.c_str(), O_CREAT | O_WRONLY | O_APPEND | O_CLOEXEC, 0644);
  if (fd_ < 0) {
    err = "open wal segment: " + std::string(strerror(errno));
    return false;
  }
  off_t end = lseek(fd_, 0, SEEK_END);
  if (end < 0) {
    err = "lseek wal segment";
    Close();
    return false;
  }
  seg_index_ = idx;
  seg_bytes_ = static_cast<uint64_t>(end);
  return true;
}

bool Wal::Open(std::string& err) {
  // mkdir -p equivalent for dir_.
  {
    std::string cur;
    for (size_t i = 0; i < dir_.size(); ++i) {
      cur.push_back(dir_[i]);
      if (dir_[i] == '/' && cur.size() > 1) mkdir(cur.c_str(), 0755);
    }
    mkdir(dir_.c_str(), 0755);
  }
  std::vector<uint64_t> segs;
  if (!ListSegments(segs)) {
    err = "cannot list wal dir: " + dir_;
    return false;
  }
  uint64_t idx = segs.empty() ? 0 : segs.back();
  if (!OpenSegment(idx, err)) return false;
  if (segs.empty()) next_seqno_ = 1;
  return true;
}

bool Wal::Append(WalRecordType type, const std::string& ticket_id, uint64_t& seqno_out,
                 std::string& err) {
  if (fd_ < 0) {
    err = "wal not open";
    return false;
  }
  if (ticket_id.size() > 4096) {
    err = "wal payload too large";
    return false;
  }
  std::vector<uint8_t> buf;
  buf.reserve(kHeaderLen + ticket_id.size() + 4);
  PutU32LE(buf, kWalMagic);
  PutU64LE(buf, next_seqno_);
  PutU16LE(buf, static_cast<uint16_t>(type));
  PutU32LE(buf, static_cast<uint32_t>(ticket_id.size()));
  buf.insert(buf.end(), ticket_id.begin(), ticket_id.end());
  uint32_t crc = Crc32c(buf.data() + 4, buf.size() - 4);
  PutU32LE(buf, crc);
  if (seg_bytes_ > 0 && seg_bytes_ + buf.size() > segment_bytes_) {
    if (!OpenSegment(seg_index_ + 1, err)) return false;
  }
  if (!WriteFull(fd_, buf.data(), buf.size())) {
    err = "wal write: " + std::string(strerror(errno));
    return false;
  }
  seg_bytes_ += buf.size();
  seqno_out = next_seqno_++;
  return true;
}

bool Wal::Flush(std::string& err) {
  if (fd_ < 0) return true;
  auto t0 = std::chrono::steady_clock::now();
  int rc = 0;
  do {
    rc = fsync(fd_);
  } while (rc < 0 && errno == EINTR);
  auto t1 = std::chrono::steady_clock::now();
  uint64_t us =
      static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
  Metrics::Instance().ObserveFsyncUs(us);
  if (rc < 0) {
    err = "wal fsync: " + std::string(strerror(errno));
    return false;
  }
  return true;
}

bool Wal::Replay(const std::function<bool(const WalRecord&)>& cb, std::string& err) {
  Close();
  mkdir(dir_.c_str(), 0755);
  std::vector<uint64_t> segs;
  if (!ListSegments(segs)) {
    err = "cannot list wal dir";
    return false;
  }
  next_seqno_ = 1;
  for (size_t si = 0; si < segs.size(); ++si) {
    std::string path = SegPath(segs[si]);
    int fd = open(path.c_str(), O_RDWR | O_CLOEXEC);
    if (fd < 0) {
      err = "open wal for replay: " + std::string(strerror(errno));
      return false;
    }
    uint64_t off = 0;
    while (true) {
      uint8_t hdr[kHeaderLen];
      bool eof = false;
      if (!PReadFull(fd, off, hdr, kHeaderLen, eof)) {
        // Torn tail: truncate and stop (valid recovery path).
        GC_LOG_WARN("wal", "torn tail at seg " + std::to_string(segs[si]) + " off " +
                               std::to_string(off) + "; truncating");
        if (ftruncate(fd, static_cast<off_t>(off)) < 0) {
          err = "ftruncate torn tail";
          close(fd);
          return false;
        }
        break;
      }
      if (eof) break;  // clean EOF at record boundary
      if (GetU32LE(hdr) != kWalMagic) {
        GC_LOG_WARN("wal", "bad magic; truncating tail at off " + std::to_string(off));
        if (ftruncate(fd, static_cast<off_t>(off)) < 0) {
          err = "ftruncate bad magic";
          close(fd);
          return false;
        }
        break;
      }
      uint64_t seq = GetU64LE(hdr + 4);
      uint16_t typ = GetU16LE(hdr + 12);
      uint32_t len = GetU32LE(hdr + 14);
      if (len > kMaxPayload) {
        GC_LOG_WARN("wal", "oversize record; truncating");
        if (ftruncate(fd, static_cast<off_t>(off)) < 0) {
          err = "ftruncate oversize";
          close(fd);
          return false;
        }
        break;
      }
      std::vector<uint8_t> rest(len + 4);
      if (!PReadFull(fd, off + kHeaderLen, rest.data(), rest.size(), eof)) {
        GC_LOG_WARN("wal", "torn payload; truncating");
        if (ftruncate(fd, static_cast<off_t>(off)) < 0) {
          err = "ftruncate torn payload";
          close(fd);
          return false;
        }
        break;
      }
      uint32_t want = GetU32LE(rest.data() + len);
      // CRC covers seqno|type|len|payload
      uint32_t crc = Crc32c(hdr + 4, 14);
      crc = Crc32cExtend(crc, rest.data(), len);
      if (crc != want) {
        GC_LOG_WARN("wal", "crc mismatch at seq " + std::to_string(seq) + "; truncating");
        if (ftruncate(fd, static_cast<off_t>(off)) < 0) {
          err = "ftruncate crc";
          close(fd);
          return false;
        }
        break;
      }
      WalRecord rec;
      rec.seqno = seq;
      rec.type = static_cast<WalRecordType>(typ);
      rec.payload.assign(rest.begin(), rest.begin() + len);
      off += kHeaderLen + len + 4;
      if (seq >= next_seqno_) next_seqno_ = seq + 1;
      if (!cb(rec)) {
        err = "replay callback failed";
        close(fd);
        return false;
      }
    }
    close(fd);
  }
  uint64_t idx = segs.empty() ? 0 : segs.back();
  if (!OpenSegment(idx, err)) return false;
  return true;
}

size_t Wal::SegmentCount() const {
  std::vector<uint64_t> segs;
  if (!ListSegments(segs)) return 0;
  return segs.size();
}

}  // namespace gatecrypt
