#include <gtest/gtest.h>

#include <cstring>
#include <string>
#include <vector>

#include "crypto/key_store.h"
#include "crypto/nonce_manager.h"
#include "crypto/secure.h"

using namespace gatecrypt;

// RFC 8032 Section 7.1 TEST 1 (empty message). Full 32-byte seed,
// 32-byte pubkey, 64-byte signature.
TEST(Crypto, Rfc8032Test1) {
  std::vector<uint8_t> seed, pub, sig;
  ASSERT_TRUE(
      HexDecode("9d61b19deffd5a60ba844af492ec2cc4"
                "4449c5697b326919703bac031cae7f60",
                seed));
  ASSERT_EQ(seed.size(), 32u);
  ASSERT_TRUE(
      HexDecode("d75a980182b10ab7d54bfed3c964073a"
                "0ee172f3daa62325af021a68f707511a",
                pub));
  ASSERT_EQ(pub.size(), 32u);
  std::vector<uint8_t> msg;  // empty
  ASSERT_TRUE(
      HexDecode("e5564300c360ac729086e2cc806e828a"
                "84877f1eb8e5d974d873e06522490155"
                "5fb8821590a33bacc61e39701cf9b46b"
                "d25bf5f0595bbe24655141438e7a100b",
                sig));
  ASSERT_EQ(sig.size(), 64u);
  // Verify with RFC pubkey (empty message: pass nullptr, 0).
  EXPECT_TRUE(Ed25519Verify(pub.data(), nullptr, 0, sig.data()));
  // And our keystore with RFC seed produces same pubkey.
  SoftwareKeyStore ks;
  ASSERT_TRUE(ks.LoadPrivate(seed));
  EXPECT_EQ(ks.GetPublicKey(), pub);
  std::vector<uint8_t> ours;
  ASSERT_TRUE(ks.Sign(nullptr, 0, ours));
  EXPECT_EQ(ours, sig);
}

// RFC 8032 Section 7.1 TEST 2 (single byte 0x72).
TEST(Crypto, Rfc8032Test2) {
  std::vector<uint8_t> seed, pub, sig;
  ASSERT_TRUE(
      HexDecode("4ccd089b28ff96da9db6c346ec114e0f"
                "5b8a319f35aba624da8cf6ed4fb8a6fb",
                seed));
  ASSERT_EQ(seed.size(), 32u);
  ASSERT_TRUE(
      HexDecode("3d4017c3e843895a92b70aa74d1b7ebc"
                "9c982ccf2ec4968cc0cd55f12af4660c",
                pub));
  ASSERT_EQ(pub.size(), 32u);
  std::vector<uint8_t> msg = {0x72};
  ASSERT_TRUE(
      HexDecode("92a009a9f0d4cab8720e820b5f642540"
                "a2b27b5416503f8fb3762223ebdb69da"
                "085ac1e43e15996e458f3613d0f11d8c"
                "387b2eaeb4302aeeb00d291612bb0c00",
                sig));
  ASSERT_EQ(sig.size(), 64u);
  EXPECT_TRUE(Ed25519Verify(pub.data(), msg.data(), msg.size(), sig.data()));
  SoftwareKeyStore ks;
  ASSERT_TRUE(ks.LoadPrivate(seed));
  EXPECT_EQ(ks.GetPublicKey(), pub);
  std::vector<uint8_t> ours;
  ASSERT_TRUE(ks.Sign(msg.data(), msg.size(), ours));
  EXPECT_EQ(ours, sig);
}

// RFC 8032 Section 7.1 TEST 3 (message bytes af82).
TEST(Crypto, Rfc8032Test3) {
  std::vector<uint8_t> seed, pub, sig, msg;
  ASSERT_TRUE(
      HexDecode("c5aa8df43f9f837bedb7442f31dcb7b1"
                "66d38535076f094b85ce3a2e0b4458f7",
                seed));
  ASSERT_TRUE(
      HexDecode("fc51cd8e6218a1a38da47ed00230f058"
                "0816ed13ba3303ac5deb911548908025",
                pub));
  ASSERT_TRUE(HexDecode("af82", msg));
  ASSERT_TRUE(
      HexDecode("6291d657deec24024827e69c3abe01a3"
                "0ce548a284743a445e3680d7db5ac3ac"
                "18ff9b538d16f290ae67f760984dc659"
                "4a7c15e9716ed28dc027beceea1ec40a",
                sig));
  ASSERT_EQ(sig.size(), 64u);
  EXPECT_TRUE(Ed25519Verify(pub.data(), msg.data(), msg.size(), sig.data()));
  SoftwareKeyStore ks;
  ASSERT_TRUE(ks.LoadPrivate(seed));
  EXPECT_EQ(ks.GetPublicKey(), pub);
  std::vector<uint8_t> ours;
  ASSERT_TRUE(ks.Sign(msg.data(), msg.size(), ours));
  EXPECT_EQ(ours, sig);
}

TEST(Crypto, TamperedSigFails) {
  SoftwareKeyStore ks;
  ASSERT_TRUE(ks.Generate());
  std::string m = "ticket-1";
  std::vector<uint8_t> sig;
  ASSERT_TRUE(ks.Sign((uint8_t*)m.data(), m.size(), sig));
  sig[0] ^= 1;
  EXPECT_FALSE(Ed25519Verify(ks.GetPublicKey().data(), (uint8_t*)m.data(), m.size(), sig.data()));
}

TEST(Crypto, ConstantTimeEqual) {
  EXPECT_TRUE(ConstantTimeEqual((uint8_t*)"ab", (uint8_t*)"ab", 2));
  EXPECT_FALSE(ConstantTimeEqual((uint8_t*)"ab", (uint8_t*)"ac", 2));
  EXPECT_FALSE(ConstantTimeEqual(std::vector<uint8_t>{1}, std::vector<uint8_t>{1, 2}));
}

TEST(Nonce, IssueConsumeOnce) {
  NonceManager nm(60000, 1024, 0);
  auto n = nm.Issue();
  ASSERT_EQ(n.size(), 16u);
  EXPECT_TRUE(nm.Consume(n));
  EXPECT_FALSE(nm.Consume(n));  // replay
}

TEST(Nonce, UnknownFails) {
  NonceManager nm(60000, 1024, 0);
  std::vector<uint8_t> fake(16, 0xAA);
  EXPECT_FALSE(nm.Consume(fake));
}

TEST(Nonce, WrongSizeFails) {
  NonceManager nm(60000, 1024, 0);
  std::vector<uint8_t> shortn(8, 1);
  EXPECT_FALSE(nm.Consume(shortn));
}

TEST(Nonce, BoundedEviction) {
  NonceManager nm(60000, 4, 0);
  std::vector<std::vector<uint8_t>> ns;
  for (int i = 0; i < 10; ++i) ns.push_back(nm.Issue());
  EXPECT_LE(nm.Size(), 4u);
}
