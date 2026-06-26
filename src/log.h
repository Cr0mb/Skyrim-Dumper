// Tiny tagged logger: writes to console + an open ofstream. Every log line
// gets a [TAG] prefix so the consolidated log file can be filtered with grep.
#pragma once
#include <cstdarg>
#include <cstdio>
#include <fstream>
#include <string>

namespace dlog {

void Init(const std::string& path);
void Shutdown();

void Write(const char* tag, const char* fmt, ...);

inline void Info  (const char* fmt, ...) { va_list a; va_start(a, fmt); char b[2048]; vsnprintf(b, sizeof(b), fmt, a); va_end(a); Write("INFO ", "%s", b); }
inline void Warn  (const char* fmt, ...) { va_list a; va_start(a, fmt); char b[2048]; vsnprintf(b, sizeof(b), fmt, a); va_end(a); Write("WARN ", "%s", b); }
inline void Error (const char* fmt, ...) { va_list a; va_start(a, fmt); char b[2048]; vsnprintf(b, sizeof(b), fmt, a); va_end(a); Write("ERROR", "%s", b); }
inline void Phase (const char* fmt, ...) { va_list a; va_start(a, fmt); char b[2048]; vsnprintf(b, sizeof(b), fmt, a); va_end(a); Write("PHASE", "%s", b); }

} // namespace dlog
