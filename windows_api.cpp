// Minimal Windows API shims for loading Oodle DLLs on Linux.
//
// Behaviour follows the public Win32/UCRT documentation. Functions the loaded
// DLL may import but which have no meaningful Linux equivalent either return a
// documented failure value or terminate the process via LinoodleFatal() (only
// for paths that are fatal on Windows too, e.g. SEH personality routines,
// RaiseException, __fastfail fallbacks, TerminateProcess). Nothing is
// written to stdout; diagnostics go to stderr. Set LINOODLE_TRACE=1 to log
// every shim call.
#include "windows_api.h"
#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <malloc.h>
#include <mutex>
#include <pthread.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

// Typedefs
typedef uint32_t UINT;
typedef int64_t LONG_PTR, * PLONG_PTR;
typedef unsigned char BYTE;
typedef uint16_t WORD;
typedef char16_t WCHAR; // Windows WCHAR is UTF-16 (2 bytes); Linux wchar_t is 4 bytes.
typedef WCHAR* LPWCH, * LPWSTR;
typedef const WCHAR* LPCWCH, * LPCWSTR;
typedef char* LPSTR;
typedef const char* LPCSTR, * LPCCH;
typedef BYTE* LPBYTE;
typedef BOOL* LPBOOL;
typedef int64_t LARGE_INTEGER;
typedef void* HANDLE;
typedef void* PVOID;
typedef int64_t INT_PTR;
typedef INT_PTR(WINAPI* FARPROC)();

typedef struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
} FILETIME, * PFILETIME;

typedef struct _STARTUPINFOW {
    DWORD   cb;
    LPWSTR  lpReserved;
    LPWSTR  lpDesktop;
    LPWSTR  lpTitle;
    DWORD   dwX;
    DWORD   dwY;
    DWORD   dwXSize;
    DWORD   dwYSize;
    DWORD   dwXCountChars;
    DWORD   dwYCountChars;
    DWORD   dwFillAttribute;
    DWORD   dwFlags;
    WORD    wShowWindow;
    WORD    cbReserved2;
    LPBYTE  lpReserved2;
    HANDLE  hStdInput;
    HANDLE  hStdOutput;
    HANDLE  hStdError;
} STARTUPINFOW, * LPSTARTUPINFOW;

typedef struct _CPINFO {
    UINT MaxCharSize;
    BYTE DefaultChar[2];
    BYTE LeadByte[12];
} CPINFO, * LPCPINFO;

// Constants
#define FALSE 0
#define TRUE 1
#define HEAP_ZERO_MEMORY 0x00000008
#define TLS_OUT_OF_INDEXES ((DWORD)0xFFFFFFFF)
#define CP_ACP 0
#define CP_OEMCP 1
#define CP_UTF8 65001
#define ERROR_FILE_NOT_FOUND 2
#define ERROR_ACCESS_DENIED 5
#define ERROR_INVALID_HANDLE 6
#define ERROR_NOT_ENOUGH_MEMORY 8
#define ERROR_CALL_NOT_IMPLEMENTED 120
#define ERROR_INVALID_PARAMETER 87
#define ERROR_INSUFFICIENT_BUFFER 122
#define ERROR_MOD_NOT_FOUND 126
#define ERROR_ENVVAR_NOT_FOUND 203
#define ERROR_NO_UNICODE_TRANSLATION 1113
#define STD_INPUT_HANDLE ((DWORD)-10)
#define STD_OUTPUT_HANDLE ((DWORD)-11)
#define STD_ERROR_HANDLE ((DWORD)-12)
#define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)
#define FILE_TYPE_CHAR 0x0002
#define KERNEL32_HANDLE ((HANDLE)0x41414141)
#define PROCESS_HEAP_HANDLE ((HANDLE)0xDEADBEEF)

static bool TraceEnabled()
{
    static const bool enabled = [] {
        const char* v = getenv("LINOODLE_TRACE");
        return v != nullptr && v[0] != '\0' && v[0] != '0';
    }();
    return enabled;
}
#define TRACE() do { if (TraceEnabled()) fprintf(stderr, "linoodle-trace: %s\n", __func__); } while (0)

[[noreturn]] static void LinoodleFatal(const char* what)
{
    fprintf(stderr, "linoodle: fatal: Oodle DLL reached unsupported Windows path: %s\n", what);
    fflush(stderr);
    abort();
}

// ---------------------------------------------------------------- UTF-16 helpers
static size_t Utf16Len(LPCWCH s)
{
    size_t n = 0;
    while (s[n] != 0) {
        n++;
    }
    return n;
}

// UTF-16 -> UTF-8. Returns false on unpaired surrogates.
static bool Utf16ToUtf8(LPCWCH src, size_t n, std::string& out)
{
    out.clear();
    for (size_t i = 0; i < n; i++) {
        uint32_t c = src[i];
        if (c >= 0xD800 && c <= 0xDBFF) {
            if (i + 1 >= n || src[i + 1] < 0xDC00 || src[i + 1] > 0xDFFF) {
                return false;
            }
            c = 0x10000 + ((c - 0xD800) << 10) + (src[i + 1] - 0xDC00);
            i++;
        }
        else if (c >= 0xDC00 && c <= 0xDFFF) {
            return false;
        }
        if (c < 0x80) {
            out.push_back(static_cast<char>(c));
        }
        else if (c < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (c >> 6)));
            out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        }
        else if (c < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (c >> 12)));
            out.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        }
        else {
            out.push_back(static_cast<char>(0xF0 | (c >> 18)));
            out.push_back(static_cast<char>(0x80 | ((c >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        }
    }
    return true;
}

// UTF-8 -> UTF-16. Returns false on invalid sequences.
static bool Utf8ToUtf16(const unsigned char* src, size_t n, std::u16string& out)
{
    out.clear();
    for (size_t i = 0; i < n;) {
        uint32_t c = src[i];
        size_t extra = 0;
        if (c < 0x80) {
            extra = 0;
        }
        else if ((c & 0xE0) == 0xC0) {
            c &= 0x1F;
            extra = 1;
        }
        else if ((c & 0xF0) == 0xE0) {
            c &= 0x0F;
            extra = 2;
        }
        else if ((c & 0xF8) == 0xF0) {
            c &= 0x07;
            extra = 3;
        }
        else {
            return false;
        }
        if (i + extra >= n && extra != 0) {
            return false;
        }
        for (size_t k = 1; k <= extra; k++) {
            if ((src[i + k] & 0xC0) != 0x80) {
                return false;
            }
            c = (c << 6) | (src[i + k] & 0x3F);
        }
        i += extra + 1;
        if (c >= 0x10000) {
            c -= 0x10000;
            out.push_back(static_cast<char16_t>(0xD800 + (c >> 10)));
            out.push_back(static_cast<char16_t>(0xDC00 + (c & 0x3FF)));
        }
        else {
            out.push_back(static_cast<char16_t>(c));
        }
    }
    return true;
}

static char g_commandLineA[] = "linoodle.exe";
static WCHAR g_commandLineW[] = u"linoodle.exe";
// Fixed, synthetic environment block (UTF-16, double-NUL terminated); the host
// environment is never passed to the DLL.
static const WCHAR g_environmentStrings[] = u"ALLUSERSPROFILE=AllUsersProfile\0APPDATA=AppData\0COMPUTERNAME=DESKTOP-ABCDEFG\0LOCALAPPDATA=LocalAppData\0";

// ---------------------------------------------------------------- KERNEL32
__thread DWORD g_lastError;
static DWORD WINAPI GetLastError()
{
    TRACE();
    return g_lastError;
}

static void WINAPI SetLastError(DWORD dwErrCode)
{
    TRACE();
    g_lastError = dwErrCode;
}

static void* WINAPI HeapAlloc(HANDLE hHeap, uint32_t dwFlags, size_t dwBytes)
{
    TRACE();
    void* p = (dwFlags & HEAP_ZERO_MEMORY) ? calloc(dwBytes ? dwBytes : 1, 1) : malloc(dwBytes ? dwBytes : 1);
    if (p == nullptr) {
        g_lastError = ERROR_NOT_ENOUGH_MEMORY;
    }
    return p;
}

static void* WINAPI HeapReAlloc(HANDLE hHeap, DWORD dwFlags, void* lpMem, size_t dwBytes)
{
    TRACE();
    if (lpMem == nullptr) {
        g_lastError = ERROR_INVALID_PARAMETER;
        return nullptr;
    }
    size_t oldSize = malloc_usable_size(lpMem);
    void* p = realloc(lpMem, dwBytes ? dwBytes : 1);
    if (p == nullptr) {
        g_lastError = ERROR_NOT_ENOUGH_MEMORY;
        return nullptr;
    }
    if ((dwFlags & HEAP_ZERO_MEMORY) && dwBytes > oldSize) {
        memset(static_cast<uint8_t*>(p) + oldSize, 0, dwBytes - oldSize);
    }
    return p;
}

static BOOL WINAPI HeapFree(HANDLE hHeap, uint32_t dwFlags, void* lpMem)
{
    TRACE();
    free(lpMem);
    return TRUE;
}

static size_t WINAPI HeapSize(HANDLE hHeap, DWORD dwFlags, PVOID lpMem)
{
    TRACE();
    if (lpMem == nullptr) {
        return static_cast<size_t>(-1);
    }
    return malloc_usable_size(lpMem);
}

static HANDLE WINAPI GetProcessHeap()
{
    TRACE();
    return PROCESS_HEAP_HANDLE;
}

static DWORD WINAPI GetCurrentThreadId()
{
    TRACE();
    return static_cast<DWORD>(syscall(__NR_gettid));
}

static DWORD WINAPI GetCurrentProcessId()
{
    TRACE();
    return static_cast<DWORD>(getpid());
}

static HANDLE WINAPI GetCurrentProcess()
{
    TRACE();
    return INVALID_HANDLE_VALUE; // pseudo handle (HANDLE)-1, as on Windows
}

static void WINAPI GetSystemTimeAsFileTime(PFILETIME lpSystemTimeAsFileTime)
{
    TRACE();
    // Deterministic: zero time (only used as security-cookie entropy).
    memset(lpSystemTimeAsFileTime, 0, sizeof(FILETIME));
}

static BOOL WINAPI QueryPerformanceCounter(LARGE_INTEGER* lpPerformanceCount)
{
    TRACE();
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    *lpPerformanceCount = (now.tv_sec * 1000000000LL) + now.tv_nsec;
    return TRUE;
}

// CRITICAL_SECTION is 40 bytes on Win64 and recursive.
static_assert(sizeof(pthread_mutex_t) <= 40, "pthread_mutex_t is not large enough");
static BOOL WINAPI InitializeCriticalSectionAndSpinCount(PVOID lpCriticalSection, DWORD dwSpinCount)
{
    TRACE();
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    int rc = pthread_mutex_init(reinterpret_cast<pthread_mutex_t*>(lpCriticalSection), &attr);
    pthread_mutexattr_destroy(&attr);
    return rc == 0;
}

static void WINAPI EnterCriticalSection(PVOID lpCriticalSection)
{
    TRACE();
    if (pthread_mutex_lock(reinterpret_cast<pthread_mutex_t*>(lpCriticalSection)) != 0) {
        LinoodleFatal("EnterCriticalSection failed");
    }
}

static void WINAPI LeaveCriticalSection(PVOID lpCriticalSection)
{
    TRACE();
    if (pthread_mutex_unlock(reinterpret_cast<pthread_mutex_t*>(lpCriticalSection)) != 0) {
        LinoodleFatal("LeaveCriticalSection failed");
    }
}

static void WINAPI DeleteCriticalSection(PVOID lpCriticalSection)
{
    TRACE();
    pthread_mutex_destroy(reinterpret_cast<pthread_mutex_t*>(lpCriticalSection));
}

static DWORD WINAPI TlsAlloc()
{
    TRACE();
    pthread_key_t threadKey;
    if (pthread_key_create(&threadKey, nullptr) == 0) {
        return threadKey;
    }
    return TLS_OUT_OF_INDEXES;
}

static BOOL WINAPI TlsSetValue(DWORD dwTlsIndex, PVOID lpTlsValue)
{
    TRACE();
    return pthread_setspecific(dwTlsIndex, lpTlsValue) == 0;
}

static PVOID WINAPI TlsGetValue(DWORD dwTlsIndex)
{
    TRACE();
    g_lastError = 0; // documented: TlsGetValue clears the last error on success
    return pthread_getspecific(dwTlsIndex);
}

static BOOL WINAPI TlsFree(DWORD dwTlsIndex)
{
    TRACE();
    return pthread_key_delete(dwTlsIndex) == 0;
}

static char* WINAPI GetCommandLineA()
{
    TRACE();
    return g_commandLineA;
}

static WCHAR* WINAPI GetCommandLineW()
{
    TRACE();
    return g_commandLineW;
}

static void WINAPI GetStartupInfoW(LPSTARTUPINFOW lpStartupInfo)
{
    TRACE();
    memset(lpStartupInfo, 0, sizeof(STARTUPINFOW));
    lpStartupInfo->cb = sizeof(STARTUPINFOW);
}

static HANDLE WINAPI GetStdHandle(DWORD nStdHandle)
{
    TRACE();
    switch (nStdHandle) {
    case STD_INPUT_HANDLE:
        return (HANDLE)0x100;
    case STD_OUTPUT_HANDLE:
        return (HANDLE)0x101;
    case STD_ERROR_HANDLE:
        return (HANDLE)0x102;
    }
    return INVALID_HANDLE_VALUE;
}

static BOOL WINAPI SetStdHandle(DWORD nStdHandle, HANDLE hHandle)
{
    TRACE();
    return TRUE;
}

static DWORD WINAPI GetFileType(HANDLE hFile)
{
    TRACE();
    return FILE_TYPE_CHAR;
}

static BOOL WINAPI WriteFile(HANDLE hFile, const void* lpBuffer, DWORD nNumberOfBytesToWrite, DWORD* lpWritten, void* lpOverlapped)
{
    TRACE();
    // stdout of the worker is a protocol channel: DLL output to either std
    // handle is redirected to stderr.
    if (hFile == (HANDLE)0x101 || hFile == (HANDLE)0x102) {
        size_t n = fwrite(lpBuffer, 1, nNumberOfBytesToWrite, stderr);
        if (lpWritten != nullptr) {
            *lpWritten = static_cast<DWORD>(n);
        }
        return TRUE;
    }
    g_lastError = ERROR_INVALID_HANDLE;
    return FALSE;
}

static BOOL WINAPI WriteConsoleW(HANDLE, const void*, DWORD, DWORD*, void*)
{
    TRACE();
    g_lastError = ERROR_INVALID_HANDLE;
    return FALSE;
}

static UINT WINAPI GetConsoleCP()
{
    TRACE();
    return CP_UTF8;
}

static BOOL WINAPI GetConsoleMode(HANDLE, DWORD* lpMode)
{
    TRACE();
    g_lastError = ERROR_INVALID_HANDLE; // not a console: CRT falls back to WriteFile
    return FALSE;
}

static BOOL WINAPI FlushFileBuffers(HANDLE)
{
    TRACE();
    fflush(stderr);
    return TRUE;
}

static BOOL WINAPI SetFilePointerEx(HANDLE, LARGE_INTEGER, LARGE_INTEGER*, DWORD)
{
    TRACE();
    g_lastError = ERROR_INVALID_HANDLE;
    return FALSE;
}

static HANDLE WINAPI CreateFileW(LPCWSTR, DWORD, DWORD, void*, DWORD, DWORD, HANDLE)
{
    TRACE();
    g_lastError = ERROR_ACCESS_DENIED; // the DLL gets no file system access
    return INVALID_HANDLE_VALUE;
}

static BOOL WINAPI CloseHandle(HANDLE)
{
    TRACE();
    return TRUE;
}

static HANDLE WINAPI FindFirstFileExW(LPCWSTR, int, void*, int, void*, DWORD)
{
    TRACE();
    g_lastError = ERROR_FILE_NOT_FOUND;
    return INVALID_HANDLE_VALUE;
}

static BOOL WINAPI FindNextFileW(HANDLE, void*)
{
    TRACE();
    g_lastError = ERROR_FILE_NOT_FOUND;
    return FALSE;
}

static BOOL WINAPI FindClose(HANDLE)
{
    TRACE();
    return TRUE;
}

static UINT WINAPI GetACP()
{
    TRACE();
    return CP_UTF8;
}

static UINT WINAPI GetOEMCP()
{
    TRACE();
    return CP_UTF8;
}

static BOOL WINAPI IsValidCodePage(UINT CodePage)
{
    TRACE();
    return CodePage == CP_UTF8 || CodePage == 20127 /* US-ASCII */;
}

static BOOL WINAPI GetCPInfo(UINT CodePage, LPCPINFO lpCPInfo)
{
    TRACE();
    if (lpCPInfo == nullptr || !(CodePage == CP_UTF8 || CodePage == CP_ACP || CodePage == CP_OEMCP)) {
        g_lastError = ERROR_INVALID_PARAMETER;
        return FALSE;
    }
    memset(lpCPInfo, 0, sizeof(*lpCPInfo));
    lpCPInfo->MaxCharSize = 4;
    lpCPInfo->DefaultChar[0] = '?';
    return TRUE;
}

static DWORD WINAPI GetThreadLocale()
{
    TRACE();
    return 0x0409; // en-US
}

static uint32_t AsciiCType1(char16_t c)
{
    // CT_CTYPE1 bits: UPPER 1, LOWER 2, DIGIT 4, SPACE 8, PUNCT 0x10,
    // CNTRL 0x20, BLANK 0x40, XDIGIT 0x80, ALPHA 0x100, DEFINED 0x200.
    if (c >= 0x80) {
        return 0x200; // defined, otherwise unclassified
    }
    int ch = static_cast<int>(c);
    uint32_t t = 0x200;
    if (isupper(ch)) t |= 0x1;
    if (islower(ch)) t |= 0x2;
    if (isdigit(ch)) t |= 0x4;
    if (isspace(ch)) t |= 0x8;
    if (ispunct(ch)) t |= 0x10;
    if (iscntrl(ch)) t |= 0x20;
    if (ch == ' ' || ch == '\t') t |= 0x40;
    if (isxdigit(ch)) t |= 0x80;
    if (isalpha(ch)) t |= 0x100;
    return t;
}

static BOOL WINAPI GetStringTypeW(DWORD dwInfoType, LPCWCH lpSrcStr, int cchSrc, WORD* lpCharType)
{
    TRACE();
    if (lpSrcStr == nullptr || lpCharType == nullptr) {
        g_lastError = ERROR_INVALID_PARAMETER;
        return FALSE;
    }
    size_t n = cchSrc < 0 ? Utf16Len(lpSrcStr) + 1 : static_cast<size_t>(cchSrc);
    for (size_t i = 0; i < n; i++) {
        lpCharType[i] = dwInfoType == 1 ? static_cast<WORD>(AsciiCType1(lpSrcStr[i])) : 0;
    }
    return TRUE;
}

static int WINAPI LCMapStringW(DWORD Locale, DWORD dwMapFlags, LPCWCH lpSrcStr, int cchSrc, WCHAR* lpDestStr, int cchDest)
{
    TRACE();
    const DWORD LCMAP_LOWERCASE = 0x100, LCMAP_UPPERCASE = 0x200;
    if (lpSrcStr == nullptr || (dwMapFlags & ~(LCMAP_LOWERCASE | LCMAP_UPPERCASE)) != 0) {
        g_lastError = ERROR_INVALID_PARAMETER;
        return 0;
    }
    size_t n = cchSrc < 0 ? Utf16Len(lpSrcStr) + 1 : static_cast<size_t>(cchSrc);
    if (cchDest == 0) {
        return static_cast<int>(n);
    }
    if (static_cast<size_t>(cchDest) < n || lpDestStr == nullptr) {
        g_lastError = ERROR_INSUFFICIENT_BUFFER;
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        char16_t c = lpSrcStr[i];
        if (c < 0x80) {
            if (dwMapFlags & LCMAP_LOWERCASE) c = static_cast<char16_t>(tolower(c));
            if (dwMapFlags & LCMAP_UPPERCASE) c = static_cast<char16_t>(toupper(c));
        }
        lpDestStr[i] = c;
    }
    return static_cast<int>(n);
}

static int WINAPI CompareStringW(DWORD Locale, DWORD dwCmpFlags, LPCWCH s1, int n1, LPCWCH s2, int n2)
{
    TRACE();
    if (s1 == nullptr || s2 == nullptr) {
        g_lastError = ERROR_INVALID_PARAMETER;
        return 0;
    }
    size_t l1 = n1 < 0 ? Utf16Len(s1) : static_cast<size_t>(n1);
    size_t l2 = n2 < 0 ? Utf16Len(s2) : static_cast<size_t>(n2);
    // Ordinal comparison: CSTR_LESS_THAN 1, CSTR_EQUAL 2, CSTR_GREATER_THAN 3.
    for (size_t i = 0; i < l1 && i < l2; i++) {
        if (s1[i] != s2[i]) {
            return s1[i] < s2[i] ? 1 : 3;
        }
    }
    return l1 == l2 ? 2 : (l1 < l2 ? 1 : 3);
}

static int WINAPI WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int32_t cchWideChar, LPSTR lpMultiByteStr, int32_t cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar)
{
    TRACE();
    if (!(CodePage == CP_ACP || CodePage == CP_UTF8) || lpWideCharStr == nullptr || cchWideChar == 0 || cbMultiByte < 0) {
        g_lastError = ERROR_INVALID_PARAMETER;
        return 0;
    }
    if (lpUsedDefaultChar != nullptr) {
        *lpUsedDefaultChar = FALSE;
    }
    size_t n = cchWideChar < 0 ? Utf16Len(lpWideCharStr) + 1 : static_cast<size_t>(cchWideChar);
    std::string out;
    if (!Utf16ToUtf8(lpWideCharStr, n, out)) {
        g_lastError = ERROR_NO_UNICODE_TRANSLATION;
        return 0;
    }
    if (cbMultiByte == 0) {
        return static_cast<int>(out.size());
    }
    if (out.size() > static_cast<size_t>(cbMultiByte) || lpMultiByteStr == nullptr) {
        g_lastError = ERROR_INSUFFICIENT_BUFFER;
        return 0;
    }
    memcpy(lpMultiByteStr, out.data(), out.size());
    return static_cast<int>(out.size());
}

static int WINAPI MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, WCHAR* lpWideCharStr, int cchWideChar)
{
    TRACE();
    if (!(CodePage == CP_ACP || CodePage == CP_UTF8) || lpMultiByteStr == nullptr || cbMultiByte == 0 || cchWideChar < 0) {
        g_lastError = ERROR_INVALID_PARAMETER;
        return 0;
    }
    size_t n = cbMultiByte < 0 ? strlen(lpMultiByteStr) + 1 : static_cast<size_t>(cbMultiByte);
    std::u16string out;
    if (!Utf8ToUtf16(reinterpret_cast<const unsigned char*>(lpMultiByteStr), n, out)) {
        g_lastError = ERROR_NO_UNICODE_TRANSLATION;
        return 0;
    }
    if (cchWideChar == 0) {
        return static_cast<int>(out.size());
    }
    if (out.size() > static_cast<size_t>(cchWideChar) || lpWideCharStr == nullptr) {
        g_lastError = ERROR_INSUFFICIENT_BUFFER;
        return 0;
    }
    memcpy(lpWideCharStr, out.data(), out.size() * sizeof(WCHAR));
    return static_cast<int>(out.size());
}

static DWORD WINAPI GetModuleFileNameA(HANDLE hModule, char* lpFilename, DWORD nSize)
{
    TRACE();
    const char* name = (hModule == nullptr) ? "C:\\linoodle\\linoodle.exe" : "C:\\linoodle\\oodle.dll";
    if (nSize == 0 || lpFilename == nullptr) {
        g_lastError = ERROR_INSUFFICIENT_BUFFER;
        return 0;
    }
    size_t len = strlen(name);
    if (len >= nSize) {
        memcpy(lpFilename, name, nSize - 1);
        lpFilename[nSize - 1] = 0;
        g_lastError = ERROR_INSUFFICIENT_BUFFER;
        return nSize;
    }
    memcpy(lpFilename, name, len + 1);
    return static_cast<DWORD>(len);
}

static DWORD WINAPI GetModuleFileNameW(HANDLE hModule, WCHAR* lpFilename, DWORD nSize)
{
    TRACE();
    const char16_t* name = (hModule == nullptr) ? u"C:\\linoodle\\linoodle.exe" : u"C:\\linoodle\\oodle.dll";
    if (nSize == 0 || lpFilename == nullptr) {
        g_lastError = ERROR_INSUFFICIENT_BUFFER;
        return 0;
    }
    size_t len = Utf16Len(name);
    if (len >= nSize) {
        memcpy(lpFilename, name, (nSize - 1) * sizeof(WCHAR));
        lpFilename[nSize - 1] = 0;
        g_lastError = ERROR_INSUFFICIENT_BUFFER;
        return nSize;
    }
    memcpy(lpFilename, name, (len + 1) * sizeof(WCHAR));
    return static_cast<DWORD>(len);
}

static LPWCH WINAPI GetEnvironmentStringsW()
{
    TRACE();
    size_t bytes = sizeof(g_environmentStrings);
    WCHAR* copy = static_cast<WCHAR*>(malloc(bytes));
    if (copy != nullptr) {
        memcpy(copy, g_environmentStrings, bytes);
    }
    return copy;
}

static BOOL WINAPI FreeEnvironmentStringsW(LPWCH penv)
{
    TRACE();
    free(penv);
    return TRUE;
}

static DWORD WINAPI GetEnvironmentVariableA(LPCSTR lpName, LPSTR lpBuffer, DWORD nSize)
{
    TRACE();
    // Deterministic: the DLL never sees the host environment.
    g_lastError = ERROR_ENVVAR_NOT_FOUND;
    return 0;
}

static BOOL WINAPI SetEnvironmentVariableW(LPCWSTR, LPCWSTR)
{
    TRACE();
    return TRUE;
}

static PVOID WINAPI EncodePointer(PVOID Ptr)
{
    TRACE();
    return (PVOID)((uint64_t)(Ptr) ^ 0x5BF0A7F83421AC42);
}

static bool Utf16EqualsAsciiNoCase(LPCWCH s, const char* a)
{
    size_t i = 0;
    for (; s[i] != 0 && a[i] != 0; i++) {
        if (s[i] >= 0x80 || tolower(static_cast<int>(s[i])) != tolower(static_cast<unsigned char>(a[i]))) {
            return false;
        }
    }
    return s[i] == 0 && a[i] == 0;
}

static HANDLE WINAPI GetModuleHandleW(LPCWSTR lpModuleName)
{
    TRACE();
    if (lpModuleName == nullptr) {
        return nullptr; // no EXE image
    }
    if (Utf16EqualsAsciiNoCase(lpModuleName, "kernel32.dll") || Utf16EqualsAsciiNoCase(lpModuleName, "kernel32")) {
        return KERNEL32_HANDLE;
    }
    g_lastError = ERROR_MOD_NOT_FOUND;
    return nullptr;
}

static BOOL WINAPI GetModuleHandleExW(DWORD dwFlags, LPCWSTR lpModuleName, HANDLE* phModule)
{
    TRACE();
    const DWORD FROM_ADDRESS = 0x4;
    HANDLE h = nullptr;
    if (!(dwFlags & FROM_ADDRESS)) {
        h = GetModuleHandleW(lpModuleName);
    }
    if (phModule != nullptr) {
        *phModule = h;
    }
    if (h == nullptr) {
        g_lastError = ERROR_MOD_NOT_FOUND;
        return FALSE;
    }
    return TRUE;
}

static FARPROC WINAPI GetProcAddress(HANDLE hModule, const char* lpProcName)
{
    TRACE();
    if (hModule == KERNEL32_HANDLE && reinterpret_cast<uintptr_t>(lpProcName) > 0xFFFF) {
        if (TraceEnabled()) {
            fprintf(stderr, "linoodle-trace: GetProcAddress(KERNEL32, %s)\n", lpProcName);
        }
        auto fn = reinterpret_cast<FARPROC>(WindowsAPI::GetInstance().GetFunction("KERNEL32.DLL", lpProcName));
        if (fn != nullptr) {
            return fn;
        }
    }
    g_lastError = 127; // ERROR_PROC_NOT_FOUND
    return nullptr;
}

static HANDLE WINAPI LoadLibraryA(LPCSTR)
{
    TRACE();
    g_lastError = ERROR_MOD_NOT_FOUND; // no further DLLs are loaded
    return nullptr;
}

static HANDLE WINAPI LoadLibraryExW(LPCWSTR, HANDLE, DWORD)
{
    TRACE();
    g_lastError = ERROR_MOD_NOT_FOUND;
    return nullptr;
}

static BOOL WINAPI FreeLibrary(HANDLE)
{
    TRACE();
    return TRUE;
}

static void WINAPI OutputDebugStringA(LPCSTR lpOutputString)
{
    TRACE();
    if (lpOutputString != nullptr) {
        fputs(lpOutputString, stderr);
    }
}

static DWORD WINAPI FormatMessageA(DWORD, const void*, DWORD, DWORD, LPSTR, DWORD, void*)
{
    TRACE();
    g_lastError = ERROR_CALL_NOT_IMPLEMENTED;
    return 0;
}

static BOOL WINAPI DisableThreadLibraryCalls(HANDLE)
{
    TRACE();
    return TRUE; // there are no thread attach notifications anyway
}

static BOOL WINAPI IsDebuggerPresent()
{
    TRACE();
    return FALSE;
}

static BOOL WINAPI IsProcessorFeaturePresent(DWORD feature)
{
    TRACE();
    // PF_* constants from winnt.h. Unknown features report FALSE.
    __builtin_cpu_init();
    switch (feature) {
    case 6:  return __builtin_cpu_supports("sse");     // PF_XMMI_INSTRUCTIONS_AVAILABLE
    case 10: return __builtin_cpu_supports("sse2");    // PF_XMMI64_INSTRUCTIONS_AVAILABLE
    case 13: return __builtin_cpu_supports("sse3");    // PF_SSE3_INSTRUCTIONS_AVAILABLE
    case 36: return __builtin_cpu_supports("ssse3");   // PF_SSSE3_INSTRUCTIONS_AVAILABLE
    case 37: return __builtin_cpu_supports("sse4.1");  // PF_SSE4_1_INSTRUCTIONS_AVAILABLE
    case 38: return __builtin_cpu_supports("sse4.2");  // PF_SSE4_2_INSTRUCTIONS_AVAILABLE
    case 39: return __builtin_cpu_supports("avx");     // PF_AVX_INSTRUCTIONS_AVAILABLE
    case 40: return __builtin_cpu_supports("avx2");    // PF_AVX2_INSTRUCTIONS_AVAILABLE
    case 41: return __builtin_cpu_supports("avx512f"); // PF_AVX512F_INSTRUCTIONS_AVAILABLE
    case 23: return FALSE; // PF_FASTFAIL_AVAILABLE: route failures through the fatal shims below
    default: return FALSE;
    }
}

static void* WINAPI SetUnhandledExceptionFilter(void*)
{
    TRACE();
    return nullptr;
}

static long WINAPI UnhandledExceptionFilter(void*)
{
    LinoodleFatal("UnhandledExceptionFilter (DLL reported a fatal error, e.g. /GS failure)");
}

static BOOL WINAPI TerminateProcess(HANDLE, UINT)
{
    LinoodleFatal("TerminateProcess");
}

static void WINAPI ExitProcess(UINT)
{
    LinoodleFatal("ExitProcess");
}

static void WINAPI RaiseException(DWORD code, DWORD, DWORD, const void*)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "RaiseException(0x%08x)", code);
    LinoodleFatal(buf);
}

static void WINAPI RtlCaptureContext(void* ctx)
{
    TRACE();
    memset(ctx, 0, 0x4d0); // sizeof(CONTEXT) on x64
}

static void* WINAPI RtlLookupFunctionEntry(uint64_t, uint64_t* imageBase, void*)
{
    TRACE();
    if (imageBase != nullptr) {
        *imageBase = 0;
    }
    return nullptr; // no unwind support; callers treat this as a leaf frame
}

static void* WINAPI RtlVirtualUnwind(DWORD, uint64_t, uint64_t, void*, void*, void**, uint64_t*, void*)
{
    LinoodleFatal("RtlVirtualUnwind");
}

static void* WINAPI RtlPcToFileHeader(void*, void** base)
{
    TRACE();
    if (base != nullptr) {
        *base = nullptr;
    }
    return nullptr;
}

static void WINAPI RtlUnwindEx(void*, void*, void*, void*, void*, void*)
{
    LinoodleFatal("RtlUnwindEx");
}

static void WINAPI InitializeSListHead(void* head)
{
    TRACE();
    memset(head, 0, 16);
}

static void* WINAPI InterlockedFlushSList(void* head)
{
    TRACE();
    // No InterlockedPush* is imported by any registered identity, so the list
    // is always empty. Atomically clear it anyway.
    __atomic_store_n(static_cast<uint64_t*>(head), 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(static_cast<uint64_t*>(head) + 1, 0, __ATOMIC_SEQ_CST);
    return nullptr;
}

// ---------------------------------------------------------------- VCRUNTIME140
static void* WINAPI vc_memcpy(void* d, const void* s, size_t n)
{
    return memcpy(d, s, n);
}

static void* WINAPI vc_memmove(void* d, const void* s, size_t n)
{
    return memmove(d, s, n);
}

static void* WINAPI vc_memset(void* d, int c, size_t n)
{
    return memset(d, c, n);
}

static int WINAPI vc_C_specific_handler(void*, void*, void*, void*)
{
    LinoodleFatal("__C_specific_handler (SEH exception dispatch)");
}

static int WINAPI vc_CxxFrameHandler3(void*, void*, void*, void*)
{
    LinoodleFatal("__CxxFrameHandler3 (C++ exception dispatch)");
}

static void WINAPI vc_std_terminate()
{
    LinoodleFatal("__std_terminate");
}

static void WINAPI vc_purecall()
{
    LinoodleFatal("_purecall");
}

static void WINAPI vc_std_type_info_destroy_list(void*)
{
    TRACE();
}

static thread_local void* t_currentException = nullptr;
static thread_local void* t_currentExceptionContext = nullptr;
static void** WINAPI vc_current_exception()
{
    TRACE();
    return &t_currentException;
}

static void** WINAPI vc_current_exception_context()
{
    TRACE();
    return &t_currentExceptionContext;
}

// ---------------------------------------------------------------- UCRT runtime / heap
typedef void(WINAPI* tPVFV)();
typedef int(WINAPI* tPIFV)();
typedef int(WINAPI* tOnexit)();

struct OnexitTable {
    tOnexit* first;
    tOnexit* last;
    tOnexit* end;
};

static std::mutex g_onexitLock;

static void WINAPI crt_initterm(tPVFV* first, tPVFV* last)
{
    TRACE();
    for (; first < last; ++first) {
        if (*first != nullptr) {
            (*first)();
        }
    }
}

static int WINAPI crt_initterm_e(tPIFV* first, tPIFV* last)
{
    TRACE();
    for (; first < last; ++first) {
        if (*first != nullptr) {
            int rc = (*first)();
            if (rc != 0) {
                return rc;
            }
        }
    }
    return 0;
}

static int WINAPI crt_initialize_onexit_table(OnexitTable* table)
{
    TRACE();
    if (table == nullptr) {
        return -1;
    }
    if (table->first == table->end) {
        table->first = table->last = table->end = nullptr;
    }
    return 0;
}

static int WINAPI crt_register_onexit_function(OnexitTable* table, tOnexit fn)
{
    TRACE();
    if (table == nullptr) {
        return -1;
    }
    std::lock_guard<std::mutex> g(g_onexitLock);
    if (table->last == table->end) {
        size_t count = static_cast<size_t>(table->last - table->first);
        size_t newCap = count == 0 ? 32 : count * 2;
        auto* n = static_cast<tOnexit*>(realloc(table->first, newCap * sizeof(tOnexit)));
        if (n == nullptr) {
            return -1;
        }
        table->first = n;
        table->last = n + count;
        table->end = n + newCap;
    }
    *table->last++ = fn;
    return 0;
}

static int WINAPI crt_execute_onexit_table(OnexitTable* table)
{
    TRACE();
    if (table == nullptr) {
        return -1;
    }
    tOnexit* first;
    tOnexit* last;
    {
        std::lock_guard<std::mutex> g(g_onexitLock);
        first = table->first;
        last = table->last;
        table->first = table->last = table->end = nullptr;
    }
    for (tOnexit* it = last; it != first;) {
        --it;
        if (*it != nullptr) {
            (*it)();
        }
    }
    free(first);
    return 0;
}

// Process-level atexit table (only used if the DLL CRT is not module-local).
static OnexitTable g_processAtexit = { nullptr, nullptr, nullptr };
static int WINAPI crt_crt_atexit(tOnexit fn)
{
    TRACE();
    return crt_register_onexit_function(&g_processAtexit, fn);
}

static void WINAPI crt_cexit()
{
    TRACE();
    crt_execute_onexit_table(&g_processAtexit);
}

static int WINAPI crt_seh_filter_dll(DWORD, void*)
{
    TRACE();
    return 0; // EXCEPTION_CONTINUE_SEARCH
}

static int WINAPI crt_configure_narrow_argv(int)
{
    TRACE();
    return 0;
}

static int WINAPI crt_initialize_narrow_environment()
{
    TRACE();
    return 0;
}

static void WINAPI crt_terminate()
{
    LinoodleFatal("terminate");
}

static void WINAPI crt_free(void* p)
{
    TRACE();
    free(p); // pairs with HeapAlloc (malloc-backed)
}

// ---------------------------------------------------------------- registry
std::string WindowsAPI::NormalizeModule(const std::string& moduleName)
{
    std::string m = moduleName;
    std::transform(m.begin(), m.end(), m.begin(), [](unsigned char c) { return static_cast<char>(toupper(c)); });
    return m;
}

void WindowsAPI::Add(const char* moduleName, const char* funcName, void* fn)
{
    m_apiMap[NormalizeModule(moduleName)][funcName] = fn;
}

#define K32(name) Add("KERNEL32.DLL", #name, reinterpret_cast<void*>(name))
#define VC(name, fn) Add("VCRUNTIME140.DLL", name, reinterpret_cast<void*>(fn))
#define CRT(name, fn) Add("API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL", name, reinterpret_cast<void*>(fn))

WindowsAPI::WindowsAPI()
{
    K32(HeapAlloc);
    K32(HeapFree);
    K32(HeapReAlloc);
    K32(HeapSize);
    K32(GetProcessHeap);
    K32(GetSystemTimeAsFileTime);
    K32(GetCurrentThreadId);
    K32(GetCurrentProcessId);
    K32(GetCurrentProcess);
    K32(QueryPerformanceCounter);
    K32(EncodePointer);
    Add("KERNEL32.DLL", "DecodePointer", reinterpret_cast<void*>(EncodePointer));
    K32(GetModuleHandleW);
    K32(GetModuleHandleExW);
    K32(GetProcAddress);
    K32(LoadLibraryA);
    K32(LoadLibraryExW);
    K32(FreeLibrary);
    K32(InitializeCriticalSectionAndSpinCount);
    K32(EnterCriticalSection);
    K32(LeaveCriticalSection);
    K32(DeleteCriticalSection);
    K32(TlsAlloc);
    K32(TlsSetValue);
    K32(TlsGetValue);
    K32(TlsFree);
    K32(GetCommandLineA);
    K32(GetCommandLineW);
    K32(GetEnvironmentStringsW);
    K32(FreeEnvironmentStringsW);
    K32(GetEnvironmentVariableA);
    K32(SetEnvironmentVariableW);
    K32(WideCharToMultiByte);
    K32(MultiByteToWideChar);
    K32(GetStartupInfoW);
    K32(GetStdHandle);
    K32(SetStdHandle);
    K32(GetFileType);
    K32(WriteFile);
    K32(WriteConsoleW);
    K32(GetConsoleCP);
    K32(GetConsoleMode);
    K32(FlushFileBuffers);
    K32(SetFilePointerEx);
    K32(CreateFileW);
    K32(CloseHandle);
    K32(FindFirstFileExW);
    K32(FindNextFileW);
    K32(FindClose);
    K32(GetLastError);
    K32(SetLastError);
    K32(GetACP);
    K32(GetOEMCP);
    K32(IsValidCodePage);
    K32(GetCPInfo);
    K32(GetThreadLocale);
    K32(GetStringTypeW);
    K32(LCMapStringW);
    K32(CompareStringW);
    K32(GetModuleFileNameA);
    K32(GetModuleFileNameW);
    K32(OutputDebugStringA);
    K32(FormatMessageA);
    K32(DisableThreadLibraryCalls);
    K32(IsDebuggerPresent);
    K32(IsProcessorFeaturePresent);
    K32(SetUnhandledExceptionFilter);
    K32(UnhandledExceptionFilter);
    K32(TerminateProcess);
    K32(ExitProcess);
    K32(RaiseException);
    K32(RtlCaptureContext);
    K32(RtlLookupFunctionEntry);
    K32(RtlVirtualUnwind);
    K32(RtlPcToFileHeader);
    K32(RtlUnwindEx);
    K32(InitializeSListHead);
    K32(InterlockedFlushSList);

    VC("memcpy", vc_memcpy);
    VC("memmove", vc_memmove);
    VC("memset", vc_memset);
    VC("__C_specific_handler", vc_C_specific_handler);
    VC("__CxxFrameHandler3", vc_CxxFrameHandler3);
    VC("__std_terminate", vc_std_terminate);
    VC("_purecall", vc_purecall);
    VC("__std_type_info_destroy_list", vc_std_type_info_destroy_list);
    VC("__current_exception", vc_current_exception);
    VC("__current_exception_context", vc_current_exception_context);

    CRT("_initterm", crt_initterm);
    CRT("_initterm_e", crt_initterm_e);
    CRT("_initialize_onexit_table", crt_initialize_onexit_table);
    CRT("_register_onexit_function", crt_register_onexit_function);
    CRT("_execute_onexit_table", crt_execute_onexit_table);
    CRT("_crt_atexit", crt_crt_atexit);
    CRT("_cexit", crt_cexit);
    CRT("_seh_filter_dll", crt_seh_filter_dll);
    CRT("_configure_narrow_argv", crt_configure_narrow_argv);
    CRT("_initialize_narrow_environment", crt_initialize_narrow_environment);
    CRT("terminate", crt_terminate);
    Add("API-MS-WIN-CRT-HEAP-L1-1-0.DLL", "free", reinterpret_cast<void*>(crt_free));
}

WindowsAPI& WindowsAPI::GetInstance() {
    static WindowsAPI instance;
    return instance;
}

void* WindowsAPI::GetFunction(const std::string& moduleName, const std::string& funcName) const
{
    auto modDataIt = m_apiMap.find(NormalizeModule(moduleName));
    if (modDataIt != m_apiMap.end()) {
        auto symDataIt = modDataIt->second.find(funcName);
        if (symDataIt != modDataIt->second.end()) {
            return symDataIt->second;
        }
    }
    return nullptr;
}

std::vector<std::string> WindowsAPI::ListFunctions() const
{
    std::vector<std::string> out;
    for (const auto& mod : m_apiMap) {
        for (const auto& fn : mod.second) {
            out.push_back(mod.first + "!" + fn.first);
        }
    }
    std::sort(out.begin(), out.end());
    return out;
}
