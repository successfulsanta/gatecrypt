#include <gtest/gtest.h>

#include <cstring>
#include <string>
#include <vector>

#include "config/config.h"
#include "crypto/key_store.h"

TEST(Smoke, ConfigDefaultsValid) {
  gatecrypt::Config c = gatecrypt::Config::Defaults();
  c.allow_plain = true;
  std::string err;
  EXPECT_TRUE(c.Validate(err)) << err;
}

TEST(Smoke, Ed25519RoundTrip) {
  gatecrypt::SoftwareKeyStore ks;
  ASSERT_TRUE(ks.Generate());
  const char* msg = "hello-gatecrypt";
  std::vector<uint8_t> sig;
  ASSERT_TRUE(ks.Sign((const uint8_t*)msg, strlen(msg), sig));
  auto pub = ks.GetPublicKey();
  EXPECT_TRUE(gatecrypt::Ed25519Verify(pub.data(), (const uint8_t*)msg, strlen(msg), sig.data()));
}
