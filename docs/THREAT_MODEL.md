# Threat Model

## Assets
Valid credentials, issuer key, device keys, WAL/checkpoints (audit).

## Adversaries & mitigations

| Threat | Mitigation |
|---|---|
| Cloning/resale (copy QR/code to another phone) | Credential bound to device pubkey at issuance; verify path constant-time compares presented key to bound key AND verifies Ed25519 over (nonce‖ticket‖context) with that key. Attacker lacks device private key. |
| Replay (capture a good response, re-enter) | 128-bit server nonce, single-use consume-first, TTL expiry, monotonic clock. Consumed-before-verify ordering kills races. |
| Double-scan burst (two gates, same ticket, same second) | Atomic CAS VALID→USED: exactly one winner; loser gets USED. Offline conflict resolved lowest-gate-wins + audit flag. |
| MITM (modify/observe transport) | TLS/mTLS (TLS≥1.2) in prod; plain only behind explicit `allow_plain` dev flag. Nonce handshake still resists replay even if observed. |
| Key extraction (steal device key) | KeyStore abstraction; TPM2/PKCS#11 backends where available; software fallback clearly labelled dev/testing-only with OPENSSL_cleanse wipe + CRYPTO_memcmp. Secrets never logged (Redact audit). |
| Insider/offline tampering (edit WAL, forge checkpoint) | WAL CRC32C detects torn/corrupt tails (truncated safely); checkpoints and revocation lists are issuer-signed; verify path checks sig before install. Unsigned local edits fail closed. |
| Revoked credential reused offline | Versioned signed revocation list persisted; hot path checks snapshot (binary search, lock-free). Rotation = version bump + re-sign. |
| DoS (flood, slowloris, oversized frames) | Token bucket per IP, conn caps, header/idle timeouts, strict max frame, Busy code under queue pressure (no unbounded memory). |
| Privilege escalation post-exploit | Drop privileges (`run_user`), `no-new-privileges`, `cap_drop: ALL`, read-only rootfs, non-root Docker user, seccomp/systemd profile recommended (see DESIGN_LOG). |

## Explicitly out of scope
- BFT/multi-writer consensus; sync is last-writer-wins by gate-ID with audit flags, not Byzantine agreement.
- Remote attestation of TPM/PKCS#11 (stubs return unavailable; wire real backends per fleet).
- Central PKI hosting/rotation ceremony; CLI covers keygen/enroll/verify only.
- Side-channel-free Ed25519 (relies on OpenSSL EVP).
- Windows/macOS (Linux epoll required).
