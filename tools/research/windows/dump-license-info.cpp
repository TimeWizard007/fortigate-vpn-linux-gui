/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Research-only Windows x64 harness for the official FortiClient
 * utilsdll.dll!GenRawLicenseInfo2 export.
 *
 * Loads the installed DLL, calls GenRawLicenseInfo2(&out, nullptr),
 * writes strlen+1 bytes to license-info.raw (including the trailing
 * NUL, matching ipsec.exe Notify 0xF100 copy), and prints KEY names
 * only. Does not print values, does not modify FortiClient, does not
 * start a VPN, and does not implement Notify 0xF100.
 *
 * Build as a 64-bit binary. A 32-bit process will not load the x64 DLL.
 */

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>

#include <cstddef>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string>
#include <vector>

namespace {

using GenRawLicenseInfo2Fn = BOOL (*)(char **out, const char *user_or_null);
using UcrtFreeFn = void (*)(void *ptr);

#ifdef _MSC_VER
#pragma comment(lib, "advapi32.lib")
#endif

constexpr wchar_t kDllPath[] =
    L"C:\\Program Files\\Fortinet\\FortiClient\\utilsdll.dll";
constexpr wchar_t kInstallDir[] =
    L"C:\\Program Files\\Fortinet\\FortiClient";
constexpr char kOutFile[] = "license-info.raw";
constexpr wchar_t kPrivateDeps[][32] = {
    L"FCCryptDLL.dll",
    L"FortiVpnDll2.dll",
    L"libssl-3-x64.dll",
    L"libcrypto-3-x64.dll",
};

bool is_x64_process() {
#if defined(_WIN64) || defined(_M_X64) || defined(__x86_64__)
    return true;
#else
    return false;
#endif
}

bool key_name_ok(const std::string &key) {
    if (key.empty() || key.size() > 64) {
        return false;
    }
    for (unsigned char ch : key) {
        const bool ok = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
                        (ch >= '0' && ch <= '9') || ch == '_';
        if (!ok) {
            return false;
        }
    }
    return true;
}

std::vector<std::string> collect_keys(const char *text, std::size_t n,
                                      std::size_t *malformed) {
    std::vector<std::string> keys;
    *malformed = 0;
    std::size_t i = 0;
    while (i < n) {
        std::size_t start = i;
        while (i < n && text[i] != '\n' && text[i] != '\r') {
            ++i;
        }
        std::size_t end = i;
        if (i < n && text[i] == '\r') {
            ++i;
        }
        if (i < n && text[i] == '\n') {
            ++i;
        }
        if (end == start) {
            continue;
        }
        const std::string line(text + start, text + end);
        const auto eq = line.find('=');
        if (eq == std::string::npos || eq == 0) {
            ++*malformed;
            continue;
        }
        const std::string key = line.substr(0, eq);
        if (!key_name_ok(key)) {
            ++*malformed;
            continue;
        }
        keys.push_back(key);
    }
    return keys;
}

UcrtFreeFn resolve_ucrt_free() {
    /* PROVEN: utilsdll.dll allocates with
     * api-ms-win-crt-heap-l1-1-0.dll!malloc (UCRT). The harness CRT
     * free() is NOT proven to share that heap: `cl` without /MD uses
     * the static CRT, and MinGW typically uses msvcrt. Do not call
     * the harness free(). After LoadLibrary of utilsdll, ucrtbase.dll
     * is the real UCRT module that API-set forwards onto. */
    HMODULE ucrt = GetModuleHandleW(L"ucrtbase.dll");
    if (ucrt == nullptr) {
        ucrt = LoadLibraryW(L"ucrtbase.dll");
    }
    if (ucrt == nullptr) {
        ucrt = GetModuleHandleW(L"api-ms-win-crt-heap-l1-1-0.dll");
    }
    if (ucrt == nullptr) {
        return nullptr;
    }
    return reinterpret_cast<UcrtFreeFn>(GetProcAddress(ucrt, "free"));
}

void release_or_leak(char *ptr, UcrtFreeFn ucrt_free) {
    if (ptr == nullptr) {
        return;
    }
    if (ucrt_free != nullptr) {
        ucrt_free(ptr);
        std::fputs("allocator: released via ucrtbase!free\n", stdout);
        return;
    }
    /* Intentionally leak this one small buffer until process exit.
     * Better than a heap mismatch. The OS reclaims it on exit. */
    std::fputs(
        "allocator: left one allocation until process exit "
        "(matching UCRT free not resolved)\n",
        stdout);
}

void print_win32_error(DWORD err) {
    std::fprintf(stderr, "GetLastError: %lu\n", static_cast<unsigned long>(err));
    wchar_t *text = nullptr;
    const DWORD n = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, err, 0, reinterpret_cast<LPWSTR>(&text), 0, nullptr);
    if (n > 0 && text != nullptr) {
        std::fwprintf(stderr, L"FormatMessage: %s", text);
        LocalFree(text);
    }
    if (err == 126) {
        std::fputs(
            "hint: ERROR_MOD_NOT_FOUND — a static dependency of utilsdll.dll "
            "was not on the default DLL search path "
            "(exe directory, System32, then current directory). "
            "Private Fortinet DLLs live beside utilsdll.dll. "
            "This harness does not change the search path.\n",
            stderr);
    } else if (err == 1114) {
        std::fputs(
            "hint: ERROR_DLL_INIT_FAILED — the DLL (or a dependency) loaded, "
            "but DllMain returned FALSE. utilsdll PROCESS_ATTACH compares "
            "GetModuleFileNameW(NULL) to HKLM INSTALLDIR and rejects "
            "unauthorized callers. A Downloads-built exe is expected to fail "
            "this check even if cwd is the FortiClient directory.\n",
            stderr);
    }
}

void print_host_context() {
    wchar_t exe[MAX_PATH];
    wchar_t cwd[MAX_PATH];
    const DWORD nexe = GetModuleFileNameW(nullptr, exe, MAX_PATH);
    const DWORD ncwd = GetCurrentDirectoryW(MAX_PATH, cwd);
    if (nexe > 0 && nexe < MAX_PATH) {
        std::fwprintf(stderr, L"host exe: %s\n", exe);
    }
    if (ncwd > 0 && ncwd < MAX_PATH) {
        std::fwprintf(stderr, L"cwd: %s\n", cwd);
    }
}

void print_safe_dependency_diagnostics() {
    std::fputs(
        "dependency existence (GetFileAttributesW in official directory; "
        "not loaded):\n",
        stderr);
    for (const wchar_t *name : kPrivateDeps) {
        wchar_t path[MAX_PATH];
        const int n = std::swprintf(path, MAX_PATH, L"%s\\%s", kInstallDir, name);
        if (n <= 0 || n >= MAX_PATH) {
            continue;
        }
        const DWORD attr = GetFileAttributesW(path);
        if (attr == INVALID_FILE_ATTRIBUTES) {
            std::fwprintf(stderr, L"  missing: %s (GetLastError=%lu)\n", path,
                          static_cast<unsigned long>(GetLastError()));
        } else {
            std::fwprintf(stderr, L"  present: %s\n", path);
        }
    }

    HKEY key = nullptr;
    const LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                                  L"SOFTWARE\\Fortinet\\FortiClient", 0,
                                  KEY_READ, &key);
    if (rc != ERROR_SUCCESS || key == nullptr) {
        std::fprintf(stderr,
                     "HKLM SOFTWARE\\Fortinet\\FortiClient: open failed "
                     "(LSTATUS=%ld)\n",
                     static_cast<long>(rc));
        return;
    }
    wchar_t installdir[MAX_PATH];
    DWORD nbytes = sizeof(installdir);
    DWORD type = 0;
    const LONG qrc = RegQueryValueExW(key, L"INSTALLDIR", nullptr, &type,
                                      reinterpret_cast<LPBYTE>(installdir),
                                      &nbytes);
    RegCloseKey(key);
    if (qrc != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ) ||
        nbytes < sizeof(wchar_t)) {
        std::fprintf(stderr,
                     "HKLM INSTALLDIR: query failed (LSTATUS=%ld type=%lu)\n",
                     static_cast<long>(qrc), static_cast<unsigned long>(type));
        return;
    }
    const size_t nchars = nbytes / sizeof(wchar_t);
    if (nchars > 0 && installdir[nchars - 1] != L'\0') {
        if (nchars >= MAX_PATH) {
            std::fputs("HKLM INSTALLDIR: value too long\n", stderr);
            return;
        }
        installdir[nchars] = L'\0';
    }
    std::fwprintf(stderr, L"HKLM INSTALLDIR: %s\n", installdir);

    wchar_t exe[MAX_PATH];
    wchar_t exe_long[MAX_PATH];
    const DWORD nexe = GetModuleFileNameW(nullptr, exe, MAX_PATH);
    if (nexe == 0 || nexe >= MAX_PATH) {
        return;
    }
    wchar_t *compare = exe;
    if (GetLongPathNameW(exe, exe_long, MAX_PATH) > 0) {
        compare = exe_long;
        std::fwprintf(stderr, L"host exe long path: %s\n", exe_long);
    }
    const size_t prefix = std::wcslen(installdir);
    const bool under_installdir =
        prefix > 0 && _wcsnicmp(compare, installdir, prefix) == 0;
    std::fprintf(stderr, "host exe under INSTALLDIR: %s\n",
                 under_installdir ? "yes" : "no");
    if (!under_installdir) {
        std::fputs(
            "hint: utilsdll DllMain PROCESS_ATTACH returns FALSE for "
            "unauthorized callers. That is sufficient for ERROR_DLL_INIT_FAILED. "
            "Do not copy this exe into the FortiClient directory.\n",
            stderr);
    }
}

int fail(const char *msg, DWORD err) {
    std::fprintf(stderr, "error: %s\n", msg);
    if (err != 0) {
        print_win32_error(err);
    }
    return 1;
}

}  // namespace

int main() {
    if (!is_x64_process()) {
        return fail("this harness must be built as Windows x64", 0);
    }

    std::fwprintf(stderr, L"LoadLibraryW path: %s\n", kDllPath);
    print_host_context();
    print_safe_dependency_diagnostics();

    HMODULE dll = LoadLibraryW(kDllPath);
    if (dll == nullptr) {
        return fail("LoadLibraryW of official utilsdll.dll failed", GetLastError());
    }

    auto fn = reinterpret_cast<GenRawLicenseInfo2Fn>(
        GetProcAddress(dll, "GenRawLicenseInfo2"));
    if (fn == nullptr) {
        DWORD err = GetLastError();
        FreeLibrary(dll);
        return fail("GetProcAddress(GenRawLicenseInfo2) failed", err);
    }

    char *out = nullptr;
    const BOOL ok = fn(&out, nullptr);
    if (!ok || out == nullptr) {
        std::fputs("GenRawLicenseInfo2: failure\n", stdout);
        UcrtFreeFn ucrt_free = resolve_ucrt_free();
        release_or_leak(out, ucrt_free);
        FreeLibrary(dll);
        return 1;
    }

    const std::size_t n = std::strlen(out);
    const std::size_t written = n + 1;
    bool embedded_nul = false;
    std::size_t lf = 0;
    std::size_t cr = 0;
    for (std::size_t i = 0; i < n; ++i) {
        if (out[i] == '\0') {
            embedded_nul = true;
        } else if (out[i] == '\n') {
            ++lf;
        } else if (out[i] == '\r') {
            ++cr;
        }
    }
    const bool trailing_lf = (n > 0 && out[n - 1] == '\n');
    const bool trailing_cr = (n > 0 && out[n - 1] == '\r');

    FILE *fp = nullptr;
#if defined(_MSC_VER)
    const errno_t open_err = fopen_s(&fp, kOutFile, "wb");
    if (open_err != 0 || fp == nullptr) {
        std::fputs("GenRawLicenseInfo2: success\n", stdout);
        std::fputs("error: could not open license-info.raw for write\n", stderr);
        release_or_leak(out, resolve_ucrt_free());
        FreeLibrary(dll);
        return 1;
    }
#else
    fp = std::fopen(kOutFile, "wb");
    if (fp == nullptr) {
        std::fputs("GenRawLicenseInfo2: success\n", stdout);
        std::fputs("error: could not open license-info.raw for write\n", stderr);
        release_or_leak(out, resolve_ucrt_free());
        FreeLibrary(dll);
        return 1;
    }
#endif

    const std::size_t nw = std::fwrite(out, 1, written, fp);
    const int flush_rc = std::fflush(fp);
    const int close_rc = std::fclose(fp);
    if (nw != written || flush_rc != 0 || close_rc != 0) {
        std::fputs("GenRawLicenseInfo2: success\n", stdout);
        std::fputs("error: incomplete write of license-info.raw\n", stderr);
        release_or_leak(out, resolve_ucrt_free());
        FreeLibrary(dll);
        return 1;
    }

    std::size_t malformed = 0;
    const std::vector<std::string> keys = collect_keys(out, n, &malformed);

    std::fputs("GenRawLicenseInfo2: success\n", stdout);
    std::fprintf(stdout, "strlen: %zu\n", n);
    std::fprintf(stdout, "bytes written: %zu\n", written);
    std::fprintf(stdout, "LF count: %zu\n", lf);
    std::fprintf(stdout, "CR count: %zu\n", cr);
    std::fprintf(stdout, "trailing LF: %s\n", trailing_lf ? "yes" : "no");
    std::fprintf(stdout, "trailing CR: %s\n", trailing_cr ? "yes" : "no");
    std::fprintf(stdout, "embedded NUL before strlen: %s\n",
                 embedded_nul ? "yes" : "no");
    std::fputs("keys:\n", stdout);
    for (const std::string &key : keys) {
        std::fprintf(stdout, "  %s\n", key.c_str());
    }
    if (malformed > 0) {
        std::fprintf(stdout, "malformed lines skipped: %zu\n", malformed);
    }

    release_or_leak(out, resolve_ucrt_free());
    FreeLibrary(dll);
    return 0;
}
