#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "protocol/framing.h"

// libFuzzer entry: strict parser must never crash; trailing/oversize rejected.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  gatecrypt::Frame fr;
  std::string err;
  if (gatecrypt::DecodeFrame(data, size, fr, err, 65536) && !fr.payload.empty()) {
    gatecrypt::VerifyRequest req;
    gatecrypt::DecodeVerifyRequest(fr.payload.data(), fr.payload.size(), req, err);
  }
  // Also fuzz inner request decoder directly.
  {
    gatecrypt::VerifyRequest req;
    gatecrypt::DecodeVerifyRequest(data, size, req, err);
  }
  return 0;
}
