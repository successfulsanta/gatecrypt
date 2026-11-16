# Protocol

All integers big-endian on the wire. WAL uses little-endian (separate spec below).

## Frame

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             MAGIC (0x47435259 "GCRY")          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          VERSION (u16=1)      |        TYPE (u16)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       PAYLOAD_LEN (u32)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         PAYLOAD (variable)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- `MAGIC` must be `0x47435259`; else Error/Malformed, connection stays open.
- `VERSION != 1` → reject (Error/Malformed).
- `PAYLOAD_LEN > max_frame_bytes` (default 65536) → reject.
- Short read (fewer than 12+LEN bytes) → wait for more; trailing bytes
  past 12+LEN in a single decode call → reject (framing layer consumes
  exactly one frame per call).
- Types: 1=NonceReq, 2=NonceResp, 3=VerifyReq, 4=VerifyResp, 255=Error.

## NonceReq → NonceResp

- NonceReq payload: empty.
- NonceResp payload: 16 raw bytes (128-bit CSPRNG, `RAND_bytes`).

## VerifyReq payload

```
nonce(16) || ticket_len(u8) || ticket(ticket_len) || device_pubkey(32)
|| signature(64) || ctx_len(u8) || ctx(ctx_len)
```

- `ticket_len` in [1,128]; `ctx_len` in [0,32].
- `signature` = Ed25519 over `nonce || ticket || ctx` with the ticket's
  bound device key.
- Any length violation → Error/Malformed; no partial processing.

## VerifyResp / Error payload

- Single byte `VerifyCode`: 0=Ok, 1=InvalidSig, 2=Replay, 3=Expired,
  4=Revoked, 5=Used, 6=Busy, 7=Malformed, 8=UnknownTicket.
- VerifyResp carries 0; Error carries non-zero.

## Backpressure

Queue full (or overload) → server replies `Error` with code `Busy`
instead of dropping silently or blocking. Clients should retry with
jitter after fetching a fresh nonce.

## WAL record (little-endian, storage only)

```
magic u32 'WAL1' | seqno u64 | type u16 | len u32 | payload | crc32c u32
```

CRC covers seqno‖type‖len‖payload. Types: 1=ISSUE, 2=USE, 3=REVOKE,
4=CHECKPOINT. Torn tail (short read / bad magic / CRC mismatch /
oversize) is truncated via ftruncate; replay stops at first torn
record.
