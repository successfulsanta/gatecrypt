# Architecture

```
 clients ──TCP/TLS──▶ EpollServer (edge-triggered, SO_REUSEPORT)
                          │ parse frames (strict, max 64KiB)
                          ▼
                    VerifyHandler (inline, mutex-guarded engine)
                          │ nonce→lookup→revoke→bind→ed25519→CAS→WAL
                          ▼
              CredentialTable (64 shards, per-entry atomic CAS)
              NonceManager (bounded, single-use, monotonic TTL)
              WAL (append+seqno+CRC32C, fsync per policy)
                          │ periodic
                          ▼
              Merkle checkpoint + revocation snapshots + sync envelopes
              /metrics /healthz /readyz on metrics_port
```

## Components

- **EpollServer** (`src/net/epoll_server.cc`): single-threaded loop per
  instance (run one per core in prod via SO_REUSEPORT multi-bind),
  non-blocking, `EPOLLET` drain-to-EAGAIN, per-IP token bucket,
  per-IP conn cap, global conn cap, header/idle timeout sweeps,
  `TCP_NODELAY`, strict `max_frame_bytes`, malformed→Error frame.
- **RingBuffer** (`src/core/ring_buffer.h`): Vyukov MPMC, power-of-two,
  sequence protocol. Push: acquire-load slot, release-store ready.
  Pop: acquire-load ready, release-store free. head_/tail_ are CAS
  hints; cache-line padded. Full→caller gets `false`→server replies
  `Busy` (backpressure, never blocks).
- **CredentialTable**: 64 shards × (mutex + map id→shared Entry).
  State is `atomic<CredState>`; `TryConsume` is single CAS
  VALID→USED (exactly-once). REVOKED terminal via CAS loop.
  Entries never reused (tombstones) → no ABA. Readers hold
  `shared_ptr` → no reclamation hazard.
- **VerifyEngine** (`src/core/verify_engine.cc`): order is
  nonce-consume → lookup → revocation → USED fast-path → device-bind
  (constant-time) → Ed25519 (nonce‖ticket‖context) → CAS → WAL
  append → ack. Policy: `EveryWrite` fsyncs inline; otherwise the
  daemon's group-commit flusher fsyncs every N ms.
- **WAL** (`src/storage/wal.cc`): `WAL1` magic, u64 seqno, CRC32C over
  header+payload, segments at `wal_segment_bytes`, torn-tail
  truncation on short-read/CRC/magic failure, replay rebuilds USED set.
- **Merkle** (`src/storage/merkle.cc` + `sync.cc`): SHA256 leaves over
  sorted used-IDs, duplicate-last for odd levels, inclusion proofs,
  signed checkpoints, signed sync envelopes, lowest-gate-wins
  conflict rule.
- **Revocation**: `shared_ptr` snapshot swap; hot path binary-searches
  sorted list, no locks.
- **TLS** (`src/net/tls.*`): OpenSSL server ctx, TLS≥1.2, optional
  client-cert verify. Plain TCP only if `allow_plain=true`.

## Commit order (durable-before-ack)

1. `TryConsume` VALID→USED (tentative, in memory).
2. `Wal::Append(USE)` assigns seqno, writes record.
3. fsync per policy (inline or flusher).
4. Ack OK to client.

Crash between 1–2: table is rebuilt from WAL on restart, so the
tentative USED vanishes → ticket stays VALID. Crash between 2–3 under
group_commit/interval: record may be lost → same reset. `EveryWrite`
closes the window at a throughput cost. WAL failure after CAS is
fail-closed: entry stays USED (never double-admit); operator
reconciles via sync/audit.

## Threading

One epoll loop thread + group-commit flusher + metrics thread in the
reference daemon. `VerifyEngine::Verify` mutates the nonce table, so
the daemon serializes handler calls with a mutex; scale by sharding
engines per IO thread (each with its own nonce/table/WAL partition or
a striped WAL) — noted as future work. RingBuffer/TSan soak tests
cover the queue; CAS burst tests cover the table.

## Threat model

See `docs/ARCHITECTURE.md` threat section (cloning, replay, MITM, key
extraction, insider/offline tampering) — summarized in README docs.
Out of scope: BFT sync, HSM attestation, PKI hosting, Windows/macOS.
