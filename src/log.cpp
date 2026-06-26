#include "log.h"
#include <ctime>
#include <cstdio>
#include <fstream>
#include <mutex>

namespace {
std::ofstream g_file;
std::mutex    g_mtx;
}

namespace dlog {

void Init(const std::string& path) {
    g_file.open(path, std::ios::out | std::ios::trunc);
}

void Shutdown() {
    if (g_file.is_open()) g_file.close();
}

void Write(const char* tag, const char* fmt, ...) {
    char body[2048];
    va_list a; va_start(a, fmt);
    vsnprintf(body, sizeof(body), fmt, a);
    va_end(a);

    time_t now = time(nullptr);
    struct tm tmv; localtime_s(&tmv, &now);
    char ts[24];
    strftime(ts, sizeof(ts), "%H:%M:%S", &tmv);

    char line[2300];
    snprintf(line, sizeof(line), "[%s] [%s] %s\n", ts, tag, body);

    std::lock_guard<std::mutex> lk(g_mtx);
    fputs(line, stdout);
    if (g_file.is_open()) { g_file << line; g_file.flush(); }
}

} // namespace dlog
