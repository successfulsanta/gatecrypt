# gatecrypt — High-Throughput Edge Verification Daemon

Offline-capable ticket/credential verifier for edge gates. Ed25519 via
OpenSSL EVP, epoll transport, lock-free queue, CAS credential table,
CRC32C WAL, Merkle checkpoints. C++20, Linux.

## Quickstart

```bash
pip install --user cmake          # if cmake missing
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
./build/gatecrypt_tests           # 46 tests
ctest --test-dir build            # same via ctest
```

Run daemon (dev, plain TCP requires explicit flag):

```bash
./build/gatecryptd --allow-plain --port 8443
```

Issue a credential and enroll a device:

```bash
./build/gatecrypt-issue keygen --out issuer
# (prints issuer pubkey hex; software fallback is dev/testing-only)
./build/gatecrypt-issue enroll --issuer-seed <hex64> --device-pub <hex64> --ticket T-1 --out cred.bin
./build/gatecrypt-issue verify --issuer-pub <hex64> --cred cred.bin
```

Benchmarks:

```bash
./build/gatecrypt-loadgen --offline                      # in-process verify path
./build/gatecrypt-loadgen --host 127.0.0.1 --conns 8 --seconds 10
```

Docker:

```bash
docker build -t gatecrypt .
docker compose up
```

## Layout

- `src/crypto` — KeyStore, SoftwareKeyStore (EVP Ed25519), NonceManager
- `src/protocol` — length-prefixed framing, strict parser
- `src/core` — RingBuffer (Vyovkov MPMC), CredentialTable (sharded+CAS), VerifyEngine
- `src/storage` — WAL (CRC32C, seqno, replay), Merkle, Revocation, Sync
- `src/net` — EpollServer (edge-triggered), TLS wrapper
- `src/observability` — logger, metrics, metrics server (/metrics /healthz /readyz)
- `src/daemon`, `src/tools` — binaries
- `tests`, `fuzz`, `benchmarks` — see docs

See `docs/ARCHITECTURE.md`, `docs/PROTOCOL.md`, `docs/DESIGN_LOG.md`.
