#pragma once

#include <stdint.h>
#include <string>
#include <unordered_map>
#include <vector>

// Tell the compiler to compile functions with WINAPI with the Windows ABI
#define WINAPI __attribute__((ms_abi))

typedef int32_t BOOL;
typedef uint32_t DWORD;
#define DLL_PROCESS_DETACH 0
#define DLL_PROCESS_ATTACH 1

// Superset shim table for KERNEL32, VCRUNTIME140 and api-ms-win-crt-*.
// Module names are matched case-insensitively (stored upper-case).
class WindowsAPI {
public:
    static WindowsAPI& GetInstance();
    // Returns nullptr if no shim exists (the loader then refuses the DLL).
    void* GetFunction(const std::string& moduleName, const std::string& funcName) const;
    // Sorted "MODULE!function" list of all shims (for static coverage checks).
    std::vector<std::string> ListFunctions() const;
    static std::string NormalizeModule(const std::string& moduleName);
    // Image base of the loaded DLL (used by GetModuleFileName/GetModuleHandle).
    void SetModule(void* base) { m_module = base; }
    void* GetModule() const { return m_module; }
    void Add(const char* moduleName, const char* funcName, void* fn);

private:
    WindowsAPI();
    ~WindowsAPI() = default;
    WindowsAPI(const WindowsAPI&) = delete;
    WindowsAPI(WindowsAPI&&) = delete;
    WindowsAPI& operator=(const WindowsAPI&) = delete;
    WindowsAPI& operator=(WindowsAPI&&) = delete;

    std::unordered_map<std::string, std::unordered_map<std::string, void*>> m_apiMap;
    void* m_module = nullptr;
};
