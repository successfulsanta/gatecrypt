#pragma once
// Append-only Write-Ahead Log.
//
// Record layout (all little-endian):
//   u32 magic (0x57414C31 'WAL1') | u64 seqno | u16 type | u32 len | payload | u32 crc32c
// CRC covers seqno|type|len|payload.
// Types: 1=ISSUE, 2=USE, 3=REVOKE, 4=CHECKPOINT.
//
// Fsync policy tradeoff (documented):
//   EveryWrite:  fsync per append — max durability, lowest throughput.
//   GroupCommit: caller batches; Flush() fsyncs — balanced default (10ms window).
//   Interval:    background fsync every N ms — max throughput, loss window = interval.
// Commit order with CAS table (see design log): TryConsume (tentative) -> WAL
// append -> fsync per policy -> ack. Crash between CAS and WAL is reconciled
// on replay: any in-memory USED without a USE record is reset to VALID during
// recovery startup (table starts empty; replay rebuilds), so no phantom USED.
//
// Recovery: replay segments in order; on short read or CRC mismatch, truncate
// torn tail (ftruncate to last good offset) and stop.
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace gatecrypt {

enum class WalRecordType : uint16_t { ISSUE = 1, USE = 2, REVOKE = 3, CHECKPOINT = 4 };

struct WalRecord {
  uint64_t seqno = 0;
  WalRecordType type = WalRecordType::USE;
  std::vector<uint8_t> payload;  // ticket_id bytes (utf-8) for ISSUE/USE/REVOKE
};

class Wal {
 public:
  Wal(const std::string& dir, uint64_t segment_bytes);
  ~Wal();

  bool Open(std::string& err);
  bool Append(WalRecordType type, const std::string& ticket_id, uint64_t& seqno_out,
              std::string& err);
  bool Flush(std::string& err);  // fsync current segment
  uint64_t NextSeqno() const { return next_seqno_; }

  // Replay all segments in order; callback per record. Truncates torn tail.
  // Returns false on unrecoverable IO error.
  bool Replay(const std::function<bool(const WalRecord&)>& cb, std::string& err);

  void Close();
  size_t SegmentCount() const;

 private:
  std::string dir_;
  uint64_t segment_bytes_;
  int fd_ = -1;
  uint64_t next_seqno_ = 1;
  uint64_t seg_index_ = 0;
  uint64_t seg_bytes_ = 0;
  std::string SegPath(uint64_t idx) const;
  bool OpenSegment(uint64_t idx, std::string& err);
  bool ListSegments(std::vector<uint64_t>& out) const;
};

}  // namespace gatecrypt
