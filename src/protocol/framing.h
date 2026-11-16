#pragma once
// Compact length-prefixed binary protocol with versioning.
#include <cstdint>
#include <string>
#include <vector>

namespace gatecrypt {

inline constexpr uint32_t kMagic = 0x47435259u;  // 'GCRY'
inline constexpr uint16_t kVersion = 1;
inline constexpr size_t kHeaderBytes = 12;  // magic(4) ver(2) type(2) len(4)
inline constexpr size_t kMaxTicketId = 128;
inline constexpr size_t kMaxContext = 32;

enum class MsgType : uint16_t {
  NonceReq = 1,
  NonceResp = 2,
  VerifyReq = 3,
  VerifyResp = 4,
  Error = 255,
};

enum class VerifyCode : uint8_t {
  Ok = 0,
  InvalidSig = 1,
  Replay = 2,
  Expired = 3,
  Revoked = 4,
  Used = 5,
  Busy = 6,
  Malformed = 7,
  UnknownTicket = 8,
};

struct Frame {
  MsgType type = MsgType::Error;
  std::vector<uint8_t> payload;
};

struct VerifyRequest {
  std::vector<uint8_t> nonce;  // 16 bytes
  std::string ticket_id;
  std::vector<uint8_t> device_pubkey;  // 32
  std::vector<uint8_t> signature;      // 64 over (nonce||ticket_id||context)
  std::string context;
};

// Wire encode/decode (big-endian header).
std::vector<uint8_t> EncodeFrame(MsgType type, const uint8_t* payload, size_t len);
inline std::vector<uint8_t> EncodeFrame(MsgType t, const std::vector<uint8_t>& p) {
  return EncodeFrame(t, p.data(), p.size());
}

// Strict parser: returns false on malformed; err filled.
bool DecodeFrame(const uint8_t* data, size_t len, Frame& out, std::string& err,
                 size_t max_frame = 65536);

bool EncodeVerifyRequest(const VerifyRequest& r, std::vector<uint8_t>& body_out, std::string& err);
bool DecodeVerifyRequest(const uint8_t* data, size_t len, VerifyRequest& out, std::string& err);

// Message signed: nonce || ticket_id bytes || context bytes.
std::vector<uint8_t> BuildSignedMessage(const uint8_t* nonce, size_t nonce_len,
                                        const std::string& ticket_id, const std::string& context);

std::vector<uint8_t> EncodeVerifyResponse(VerifyCode code);
VerifyCode DecodeVerifyResponse(const uint8_t* data, size_t len);

const char* ToString(VerifyCode c);

}  // namespace gatecrypt
