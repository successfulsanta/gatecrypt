#pragma once
// Revocation hot-path view (lock-free shared_ptr swap in real store).
#include <memory>
#include <string>

#include "storage/merkle.h"

namespace gatecrypt {
using RevocationView = std::shared_ptr<RevocationList> (*)();
}  // namespace gatecrypt
