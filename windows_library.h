#pragma once

#include "windows_api.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <unordered_map>

// Error raised by the loader; `code` is a linoodle_status value.
class LoaderError : public std::runtime_error {
public:
    LoaderError(int code, const std::string& msg) : std::runtime_error(msg), m_code(code) {}
    int code() const { return m_code; }
private:
    int m_code;
};

class MappedMemory {
public:
    MappedMemory(void* mapping, size_t size);
    MappedMemory(const MappedMemory&) = delete;
    MappedMemory(MappedMemory&& other);
    MappedMemory& operator=(const MappedMemory&) = delete;
    MappedMemory& operator=(MappedMemory&&) = delete;
    ~MappedMemory();
    operator uint8_t* () const { return reinterpret_cast<uint8_t*>(m_mapping); }
    operator void* () const { return reinterpret_cast<void*>(m_mapping); }
    void* ptr() const { return reinterpret_cast<void*>(m_mapping); }
    size_t size() const { return m_size; }
private:
    void* m_mapping;
    size_t m_size;
};

typedef BOOL(WINAPI* tEntryPoint)(void* hinstDLL, DWORD fdwReason, void* lpReserved);

// Import/export names as read from the PE tables. Imports are
// "MODULE.DLL!function" with the module upper-cased.
struct PeTables {
    std::set<std::string> imports;
    std::set<std::string> exports;
};

class WindowsLibrary {
public:
    WindowsLibrary(MappedMemory&& mapping, std::unordered_map<std::string, void*>&& exports, tEntryPoint entryPoint);
    WindowsLibrary(const WindowsLibrary&) = delete;
    WindowsLibrary(WindowsLibrary&& other) = delete;
    WindowsLibrary& operator=(const WindowsLibrary&) = delete;
    WindowsLibrary& operator=(WindowsLibrary&&) = delete;
    ~WindowsLibrary();
    // Returns nullptr when the export does not exist.
    void* GetExport(const std::string& exportName) const;
    void* GetBaseAddress();

    // Points gs at this thread's fake TEB. Must precede every call into the DLL.
    static void SetupCall();

    // Reads the import/export tables of a PE image held in memory.
    static PeTables ReadTables(const uint8_t* image, size_t size);

    // Maps, relocates and links the PE image from `image` (the caller-owned,
    // already hashed bytes) and runs DllMain(PROCESS_ATTACH). Every import
    // must resolve to a shim; otherwise LoaderError(LINOODLE_E_UNRESOLVED_IMPORT).
    static std::unique_ptr<WindowsLibrary> LoadFromMemory(const uint8_t* image, size_t size);
private:
    MappedMemory m_mapping;
    std::unordered_map<std::string, void*> m_exports;
    tEntryPoint m_entryPoint;
};
