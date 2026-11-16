# Design decisions

1. **Sharded mutex table + atomic CAS** over fully lock-free map.
   Rationale: auditability, simpler reclamation (shared_ptr tombstones,
   no ABA), per-entry CAS still gives lock-free fast path for the
   contended transition. Alternative: hazard-pointer table — higher
   complexity, marginal gain at gate throughput.
2. **Fsync default = group_commit 10ms.** Balances edge durability vs
   throughput. every_write = max durability, ~10× slower. interval =
   max throughput, loss window = interval. Documented in wal.h.
3. **Commit order CAS→WAL→ack** with replay reconciliation (unlogged
   USED vanishes on restart). Alternative WAL→CAS risks acking
   un-consumed state; chosen order is fail-closed against double-admit.
4. **Config = key=value file + GATECRYPT_* env.** No TOML/YAML deps;
   strict Validate() fail-fast.
5. **Daemon serializes Verify calls** (nonce table mutation) with a
   mutex; scale-out = shard engines per IO thread. RingBuffer stays as
   the transport→worker handoff primitive (tested, benchmarked).
6. **Plain TCP only behind `--allow-plain`/`allow_plain`.** Fail-closed
   default; TLS≥1.2 + optional mTLS via OpenSSL.
7. **Conflict rule lowest-gate-wins** for offline double-scan sync.
   Deterministic, auditable; loser flagged DUPLICATE.
8. **Software KeyStore labelled dev/testing-only.** TPM2/PKCS#11 stubs
   return unavailable; wire per fleet.
