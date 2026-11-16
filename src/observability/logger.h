#pragma once
// Structured JSON logging, minimal deps. No secrets in logs.
#include <string>

namespace gatecrypt {

enum class LogLevel { Debug = 0, Info = 1, Warn = 2, Error = 3 };

void SetLogLevel(LogLevel lvl);
void SetLogLevelFromString(const std::string& s);
LogLevel GetLogLevel();

void Log(LogLevel lvl, const std::string& component, const std::string& msg);

// Redacts values whose key hints at secrecy.
std::string Redact(const std::string& key, const std::string& value);

#define GC_LOG_DEBUG(c, m) ::gatecrypt::Log(::gatecrypt::LogLevel::Debug, (c), (m))
#define GC_LOG_INFO(c, m) ::gatecrypt::Log(::gatecrypt::LogLevel::Info, (c), (m))
#define GC_LOG_WARN(c, m) ::gatecrypt::Log(::gatecrypt::LogLevel::Warn, (c), (m))
#define GC_LOG_ERROR(c, m) ::gatecrypt::Log(::gatecrypt::LogLevel::Error, (c), (m))

}  // namespace gatecrypt
