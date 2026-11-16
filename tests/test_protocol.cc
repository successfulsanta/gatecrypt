#include <gtest/gtest.h>

#include "protocol/framing.h"

using namespace gatecrypt;

TEST(Protocol, FrameRoundTrip) {
  std::vector<uint8_t> p = {1, 2, 3};
  auto f = EncodeFrame(MsgType::VerifyReq, p);
  Frame out;
  std::string err;
  ASSERT_TRUE(DecodeFrame(f.data(), f.size(), out, err)) << err;
  EXPECT_EQ(out.type, MsgType::VerifyReq);
  EXPECT_EQ(out.payload, p);
}

TEST(Protocol, BadMagic) {
  auto f = EncodeFrame(MsgType::VerifyReq, nullptr, 0);
  f[0] ^= 0xFF;
  Frame out;
  std::string err;
  EXPECT_FALSE(DecodeFrame(f.data(), f.size(), out, err));
}

TEST(Protocol, Truncated) {
  auto f = EncodeFrame(MsgType::VerifyReq, nullptr, 0);
  Frame out;
  std::string err;
  EXPECT_FALSE(DecodeFrame(f.data(), 4, out, err));
}

TEST(Protocol, OversizeRejected) {
  std::vector<uint8_t> big(70000, 1);
  auto f = EncodeFrame(MsgType::VerifyReq, big);
  Frame out;
  std::string err;
  EXPECT_FALSE(DecodeFrame(f.data(), f.size(), out, err, 65536));
}

TEST(Protocol, TrailingBytesRejected) {
  auto f = EncodeFrame(MsgType::VerifyReq, nullptr, 0);
  f.push_back(0xFF);
  Frame out;
  std::string err;
  EXPECT_FALSE(DecodeFrame(f.data(), f.size(), out, err));
}

TEST(Protocol, VersionMismatch) {
  auto f = EncodeFrame(MsgType::VerifyReq, nullptr, 0);
  f[4] = 0;
  f[5] = 99;  // version 99
  Frame out;
  std::string err;
  EXPECT_FALSE(DecodeFrame(f.data(), f.size(), out, err));
}

TEST(Protocol, VerifyRequestRoundTrip) {
  VerifyRequest r;
  r.nonce = std::vector<uint8_t>(16, 0x11);
  r.ticket_id = "T-123";
  r.device_pubkey = std::vector<uint8_t>(32, 0x22);
  r.signature = std::vector<uint8_t>(64, 0x33);
  r.context = "gate-a";
  std::vector<uint8_t> body;
  std::string err;
  ASSERT_TRUE(EncodeVerifyRequest(r, body, err)) << err;
  VerifyRequest d;
  ASSERT_TRUE(DecodeVerifyRequest(body.data(), body.size(), d, err)) << err;
  EXPECT_EQ(d.ticket_id, r.ticket_id);
  EXPECT_EQ(d.nonce, r.nonce);
  EXPECT_EQ(d.device_pubkey, r.device_pubkey);
  EXPECT_EQ(d.signature, r.signature);
  EXPECT_EQ(d.context, r.context);
}

TEST(Protocol, VerifyRequestBadNonce) {
  VerifyRequest r;
  r.nonce = std::vector<uint8_t>(8, 1);
  r.ticket_id = "T";
  r.device_pubkey = std::vector<uint8_t>(32, 2);
  r.signature = std::vector<uint8_t>(64, 3);
  std::vector<uint8_t> body;
  std::string err;
  EXPECT_FALSE(EncodeVerifyRequest(r, body, err));
}

TEST(Protocol, SignedMessageFormat) {
  std::vector<uint8_t> n(16, 0xAB);
  auto m = BuildSignedMessage(n.data(), n.size(), "T1", "ctx");
  ASSERT_EQ(m.size(), 16u + 2 + 3);
  EXPECT_EQ(m[16], 'T');
}
