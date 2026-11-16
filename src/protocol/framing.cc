#include "protocol/framing.h"

#include <cstring>

namespace gatecrypt {

static void Put32BE(std::vector<uint8_t>& o, uint32_t v) {
  o.push_back((uint8_t)(v >> 24));
  o.push_back((uint8_t)(v >> 16));
  o.push_back((uint8_t)(v >> 8));
  o.push_back((uint8_t)v);
}

static void Put16BE(std::vector<uint8_t>& o, uint16_t v) {
  o.push_back((uint8_t)(v >> 8));
  o.push_back((uint8_t)v);
}

static uint32_t Get32BE(const uint8_t* p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint16_t Get16BE(const uint8_t* p) { return (uint16_t)(((uint16_t)p[0] << 8) | p[1]); }

std::vector<uint8_t> EncodeFrame(MsgType type, const uint8_t* payload, size_t len) {
  std::vector<uint8_t> o;
  o.reserve(kHeaderBytes + len);
  Put32BE(o, kMagic);
  Put16BE(o, kVersion);
  Put16BE(o, (uint16_t)type);
  Put32BE(o, (uint32_t)len);
  if (len && payload) o.insert(o.end(), payload, payload + len);
  return o;
}

bool DecodeFrame(const uint8_t* data, size_t len, Frame& out, std::string& err, size_t max_frame) {
  if (len < kHeaderBytes) {
    err = "frame too short";
    return false;
  }
  if (Get32BE(data) != kMagic) {
    err = "bad magic";
    return false;
  }
  uint16_t ver = Get16BE(data + 4);
  if (ver != kVersion) {
    err = "unsupported version";
    return false;
  }
  uint16_t t = Get16BE(data + 6);
  uint32_t plen = Get32BE(data + 8);
  if (plen > max_frame) {
    err = "frame too large";
    return false;
  }
  if (len < kHeaderBytes + plen) {
    err = "truncated payload";
    return false;
  }
  if (len > kHeaderBytes + plen) {
    err = "trailing bytes";
    return false;
  }
  out.type = (MsgType)t;
  out.payload.assign(data + kHeaderBytes, data + kHeaderBytes + plen);
  return true;
}

bool EncodeVerifyRequest(const VerifyRequest& r, std::vector<uint8_t>& body_out, std::string& err) {
  if (r.nonce.size() != 16) {
    err = "nonce must be 16 bytes";
    return false;
  }
  if (r.ticket_id.empty() || r.ticket_id.size() > kMaxTicketId) {
    err = "bad ticket_id length";
    return false;
  }
  if (r.device_pubkey.size() != 32) {
    err = "device_pubkey must be 32 bytes";
    return false;
  }
  if (r.signature.size() != 64) {
    err = "signature must be 64 bytes";
    return false;
  }
  if (r.context.size() > kMaxContext) {
    err = "context too large";
    return false;
  }
  body_out.clear();
  body_out.insert(body_out.end(), r.nonce.begin(), r.nonce.end());
  body_out.push_back((uint8_t)r.ticket_id.size());
  body_out.insert(body_out.end(), r.ticket_id.begin(), r.ticket_id.end());
  body_out.insert(body_out.end(), r.device_pubkey.begin(), r.device_pubkey.end());
  body_out.insert(body_out.end(), r.signature.begin(), r.signature.end());
  body_out.push_back((uint8_t)r.context.size());
  body_out.insert(body_out.end(), r.context.begin(), r.context.end());
  return true;
}

bool DecodeVerifyRequest(const uint8_t* data, size_t len, VerifyRequest& out, std::string& err) {
  size_t pos = 0;
  auto need = [&](size_t n) { return pos + n <= len; };
  if (!need(16)) {
    err = "truncated nonce";
    return false;
  }
  out.nonce.assign(data, data + 16);
  pos += 16;
  if (!need(1)) {
    err = "truncated ticket len";
    return false;
  }
  uint8_t tlen = data[pos++];
  if (tlen == 0 || tlen > kMaxTicketId) {
    err = "bad ticket len";
    return false;
  }
  if (!need(tlen)) {
    err = "truncated ticket";
    return false;
  }
  out.ticket_id.assign((const char*)data + pos, tlen);
  pos += tlen;
  if (!need(32)) {
    err = "truncated pubkey";
    return false;
  }
  out.device_pubkey.assign(data + pos, data + pos + 32);
  pos += 32;
  if (!need(64)) {
    err = "truncated sig";
    return false;
  }
  out.signature.assign(data + pos, data + pos + 64);
  pos += 64;
  if (!need(1)) {
    err = "truncated ctx len";
    return false;
  }
  uint8_t clen = data[pos++];
  if (clen > kMaxContext) {
    err = "ctx too large";
    return false;
  }
  if (!need(clen)) {
    err = "truncated ctx";
    return false;
  }
  out.context.assign((const char*)data + pos, clen);
  pos += clen;
  if (pos != len) {
    err = "trailing bytes in verify request";
    return false;
  }
  return true;
}

std::vector<uint8_t> BuildSignedMessage(const uint8_t* nonce, size_t nonce_len,
                                        const std::string& ticket_id, const std::string& context) {
  std::vector<uint8_t> m;
  m.reserve(nonce_len + ticket_id.size() + context.size());
  m.insert(m.end(), nonce, nonce + nonce_len);
  m.insert(m.end(), ticket_id.begin(), ticket_id.end());
  m.insert(m.end(), context.begin(), context.end());
  return m;
}

std::vector<uint8_t> EncodeVerifyResponse(VerifyCode code) {
  return std::vector<uint8_t>{(uint8_t)code};
}

VerifyCode DecodeVerifyResponse(const uint8_t* data, size_t len) {
  if (len < 1) return VerifyCode::Malformed;
  return (VerifyCode)data[0];
}

const char* ToString(VerifyCode c) {
  switch (c) {
    case VerifyCode::Ok:
      return "ok";
    case VerifyCode::InvalidSig:
      return "invalid_sig";
    case VerifyCode::Replay:
      return "replay";
    case VerifyCode::Expired:
      return "expired";
    case VerifyCode::Revoked:
      return "revoked";
    case VerifyCode::Used:
      return "used";
    case VerifyCode::Busy:
      return "busy";
    case VerifyCode::Malformed:
      return "malformed";
    case VerifyCode::UnknownTicket:
      return "unknown_ticket";
  }
  return "unknown";
}

}  // namespace gatecrypt
