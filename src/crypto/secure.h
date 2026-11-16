#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
namespace gatecrypt {
void SecureWipe(void* ptr, size_t n);
bool ConstantTimeEqual(const uint8_t* a, const uint8_t* b, size_t n);
bool ConstantTimeEqual(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);
}  // namespace gatecrypt
