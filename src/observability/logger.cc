#include "observability/logger.h"

#include <atomic>
#include <cctype>
#include <chrono>
#include <ctime>
#include <iostream>
#include <mutex>
#include <sstream>

namespace gatecrypt {
namespace {
std::atomic<int> g_level{1};
std::mutex g_mu;
const char* Name(LogLevel l) {
  switch (l) {
    case LogLevel::Debug:
      return "DEBUG";
    case LogLevel::Info:
      return "INFO";
    case LogLevel::Warn:
      return "WARN";
    case LogLevel::Error:
      return "ERROR";
  }
  return "INFO";
}
}  // namespace
void SetLogLevel(LogLevel lvl) { g_level.store((int)lvl); }
void SetLogLevelFromString(const std::string& s) {
  if (s == "debug")
    SetLogLevel(LogLevel::Debug);
  else if (s == "warn" || s == "warning")
    SetLogLevel(LogLevel::Warn);
  else if (s == "error")
    SetLogLevel(LogLevel::Error);
  else
    SetLogLevel(LogLevel::Info);
}
LogLevel GetLogLevel() { return (LogLevel)g_level.load(); }
void Log(LogLevel lvl, const std::string& component, const std::string& msg) {
  if ((int)lvl < g_level.load()) return;
  auto now = std::chrono::system_clock::now();
  std::time_t t = std::chrono::system_clock::to_time_t(now);
  std::ostringstream os;
  os << "{\"ts\":" << (long long)t << ",\"level\":\"" << Name(lvl) << "\",\"comp\":\"" << component
     << "\",\"msg\":\"" << msg << "\"}\n";
  std::lock_guard<std::mutex> lk(g_mu);
  std::cerr << os.str();
}
std::string Redact(const std::string& key, const std::string& value) {
  std::string k;
  k.resize(key.size());
  for (size_t i = 0; i < key.size(); ++i) k[i] = (char)tolower(key[i]);
  if (k.find("key") != std::string::npos || k.find("secret") != std::string::npos ||
      k.find("sig") != std::string::npos || k.find("token") != std::string::npos)
    return "[REDACTED len=" + std::to_string(value.size()) + "]";
  return value;
}
}  // namespace gatecrypt
