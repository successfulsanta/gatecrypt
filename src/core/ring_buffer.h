#pragma once
// Lock-free MPMC bounded ring (Vyukov-style).
// Used as SPMC in production (one dispatcher or many IO producers -> worker pool).
// For the daemon we use it MPMC-safe so any IO thread can push.
//
// Memory ordering reasoning (documented):
//  - Cell.sequence is the synchronization point.
//  - Push: load sequence with acquire; if slot free, store payload (plain),
//    then store sequence = pos+1 with release. Release pairs with Pop's acquire
//    load, ensuring payload is visible before the slot is marked ready.
//  - Pop: load sequence with acquire; if slot ready, load payload, then store
//    sequence = pos+capacity with release to hand the slot back. Release pairs
//    with the next Push's acquire load.
//  - head_/tail_ are only hints for claiming slots via CAS; the sequence
//    protocol provides correctness even under contention. head/tail use
//    relaxed loads in the fast path and CAS (acq_rel on success) for claiming.
//  - Cache-line padding (64B) separates head_/tail_ to avoid false sharing.
//
// Capacity must be power of two.
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

namespace gatecrypt {

template <typename T>
class RingBuffer {
 public:
  explicit RingBuffer(size_t capacity) : cap_(RoundUpPow2(capacity)), mask_(cap_ - 1) {
    cells_ = std::make_unique<Cell[]>(cap_);
    for (size_t i = 0; i < cap_; ++i) cells_[i].seq.store(i, std::memory_order_relaxed);
  }

  RingBuffer(const RingBuffer&) = delete;
  RingBuffer& operator=(const RingBuffer&) = delete;

  size_t capacity() const { return cap_; }

  // false when full -> caller must respond BUSY (backpressure, never block).
  bool TryPush(T item) {
    size_t pos = tail_.load(std::memory_order_relaxed);
    while (true) {
      Cell& c = cells_[pos & mask_];
      size_t seq = c.seq.load(std::memory_order_acquire);
      int64_t diff = (int64_t)seq - (int64_t)pos;
      if (diff == 0) {
        if (tail_.compare_exchange_weak(pos, pos + 1, std::memory_order_acq_rel,
                                        std::memory_order_relaxed)) {
          c.data = std::move(item);
          c.seq.store(pos + 1, std::memory_order_release);
          return true;
        }
        // CAS failed: pos updated, retry.
      } else if (diff < 0) {
        return false;  // full
      } else {
        pos = tail_.load(std::memory_order_relaxed);
      }
    }
  }

  bool TryPop(T& out) {
    size_t pos = head_.load(std::memory_order_relaxed);
    while (true) {
      Cell& c = cells_[pos & mask_];
      size_t seq = c.seq.load(std::memory_order_acquire);
      int64_t diff = (int64_t)seq - (int64_t)(pos + 1);
      if (diff == 0) {
        if (head_.compare_exchange_weak(pos, pos + 1, std::memory_order_acq_rel,
                                        std::memory_order_relaxed)) {
          out = std::move(c.data);
          c.seq.store(pos + cap_, std::memory_order_release);
          return true;
        }
      } else if (diff < 0) {
        return false;  // empty
      } else {
        pos = head_.load(std::memory_order_relaxed);
      }
    }
  }

  size_t ApproxSize() const {
    size_t t = tail_.load(std::memory_order_relaxed);
    size_t h = head_.load(std::memory_order_relaxed);
    return t >= h ? (t - h) : 0;
  }

 private:
  struct Cell {
    std::atomic<size_t> seq{0};
    T data{};
  };
  static size_t RoundUpPow2(size_t v) {
    if (v < 2) return 2;
    size_t p = 1;
    while (p < v) p <<= 1;
    return p;
  }
  const size_t cap_;
  const size_t mask_;
  std::unique_ptr<Cell[]> cells_;
  alignas(64) std::atomic<size_t> head_{0};
  alignas(64) std::atomic<size_t> tail_{0};
};

}  // namespace gatecrypt
