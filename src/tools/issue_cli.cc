#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "crypto/key_store.h"

namespace {
using namespace gatecrypt;

int Usage() {
  std::cerr << "usage:\n"
               "  gatecrypt-issue keygen --out <prefix>\n"
               "  gatecrypt-issue enroll --issuer-seed <hex64> --device-pub <hex64> "
               "--ticket <id> --out <cred.bin>\n"
               "  gatecrypt-issue verify --issuer-pub <hex64> --cred <cred.bin>\n";
  return 2;
}

bool WriteFile(const std::string& p, const std::vector<uint8_t>& b) {
  std::ofstream f(p, std::ios::binary | std::ios::trunc);
  if (!f.good()) return false;
  f.write((const char*)b.data(), (std::streamsize)b.size());
  return f.good();
}

bool ReadFile(const std::string& p, std::vector<uint8_t>& b) {
  std::ifstream f(p, std::ios::binary);
  if (!f.good()) return false;
  f.seekg(0, std::ios::end);
  long n = (long)f.tellg();
  f.seekg(0);
  b.resize(n > 0 ? (size_t)n : 0);
  if (n) f.read((char*)b.data(), n);
  return f.good();
}

std::string Arg(int argc, char** argv, const std::string& name) {
  for (int i = 0; i + 1 < argc; ++i)
    if (argv[i] == name) return argv[i + 1];
  return "";
}

// Credential binding file: ticket_len(1)||ticket||device_pub(32)||issuer_sig(64).
// issuer_sig = Ed25519_issuer(ticket || device_pub).
std::vector<uint8_t> CredBytes(const std::string& ticket, const std::vector<uint8_t>& devpub,
                               const std::vector<uint8_t>& sig) {
  std::vector<uint8_t> o;
  o.push_back((uint8_t)ticket.size());
  o.insert(o.end(), ticket.begin(), ticket.end());
  o.insert(o.end(), devpub.begin(), devpub.end());
  o.insert(o.end(), sig.begin(), sig.end());
  return o;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) return Usage();
  std::string cmd = argv[1];
  if (cmd == "keygen") {
    std::string out = Arg(argc, argv, "--out");
    if (out.empty()) return Usage();
    SoftwareKeyStore ks;
    if (!ks.Generate()) {
      std::cerr << "keygen failed\n";
      return 1;
    }
    // Export: raw pubkey hex on stdout; private seed irrecoverable from EVP,
    // so export DER for persistence (dev/testing only; HSM in prod).
    std::cout << HexEncode(ks.GetPublicKey().data(), 32) << "\n";
    std::cerr << "note: software fallback dev/testing-only backend\n";
    return 0;
  }
  if (cmd == "enroll") {
    std::string seedhex = Arg(argc, argv, "--issuer-seed");
    std::string devhex = Arg(argc, argv, "--device-pub");
    std::string ticket = Arg(argc, argv, "--ticket");
    std::string out = Arg(argc, argv, "--out");
    if (seedhex.empty() || devhex.empty() || ticket.empty() || out.empty()) return Usage();
    std::vector<uint8_t> seed, devpub;
    if (!HexDecode(seedhex, seed) || seed.size() != 32) {
      std::cerr << "bad issuer seed\n";
      return 1;
    }
    if (!HexDecode(devhex, devpub) || devpub.size() != 32) {
      std::cerr << "bad device pub\n";
      return 1;
    }
    SoftwareKeyStore issuer;
    if (!issuer.LoadPrivate(seed)) {
      std::cerr << "bad issuer key\n";
      return 1;
    }
    std::vector<uint8_t> msg;
    msg.insert(msg.end(), ticket.begin(), ticket.end());
    msg.insert(msg.end(), devpub.begin(), devpub.end());
    std::vector<uint8_t> sig;
    if (!issuer.Sign(msg.data(), msg.size(), sig)) {
      std::cerr << "sign failed\n";
      return 1;
    }
    if (!WriteFile(out, CredBytes(ticket, devpub, sig))) {
      std::cerr << "write failed\n";
      return 1;
    }
    std::cout << "enrolled " << ticket << "\n";
    return 0;
  }
  if (cmd == "verify") {
    std::string pubhex = Arg(argc, argv, "--issuer-pub");
    std::string cred = Arg(argc, argv, "--cred");
    if (pubhex.empty() || cred.empty()) return Usage();
    std::vector<uint8_t> pub, raw;
    if (!HexDecode(pubhex, pub) || !ReadFile(cred, raw)) {
      std::cerr << "bad inputs\n";
      return 1;
    }
    if (raw.size() < 1 + 32 + 64) {
      std::cerr << "cred too short\n";
      return 1;
    }
    size_t tlen = raw[0];
    if (raw.size() != 1 + tlen + 32 + 64) {
      std::cerr << "cred malformed\n";
      return 1;
    }
    std::string ticket((char*)raw.data() + 1, tlen);
    const uint8_t* devpub = raw.data() + 1 + tlen;
    const uint8_t* sig = devpub + 32;
    std::vector<uint8_t> msg;
    msg.insert(msg.end(), ticket.begin(), ticket.end());
    msg.insert(msg.end(), devpub, devpub + 32);
    bool ok = Ed25519Verify(pub.data(), msg.data(), msg.size(), sig);
    std::cout << (ok ? "VALID\n" : "INVALID\n");
    return ok ? 0 : 1;
  }
  return Usage();
}
