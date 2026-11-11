#include <utility>
#include "windows_library.h"
#include "linoodle.h"
#include "windows_api.h"
#include <asm/prctl.h>
#include <asm/unistd_64.h>
#include <cstring>
#include <memory>
#include <pe-parse/parse.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>

MappedMemory::MappedMemory(void* mapping, size_t size) :
    m_mapping(mapping),
    m_size(size)
{

}

MappedMemory::MappedMemory(MappedMemory&& other) :
    m_mapping(std::exchange(other.m_mapping, nullptr)),
    m_size(std::exchange(other.m_size, 0))
{

}

MappedMemory::~MappedMemory()
{
    if (m_mapping != nullptr) {
        munmap(m_mapping, m_size);
    }
}

// Fake Windows x64 TEB/PEB. Only the documented NT_TIB fields, ClientId and
// the PEB pointer are populated; everything else stays zero. One TEB per
// thread, initialized once (the old code zeroed it before every call).
namespace {
constexpr size_t kTebSize = 0x2000;
constexpr size_t kTebStackBase = 0x08;
constexpr size_t kTebStackLimit = 0x10;
constexpr size_t kTebSelf = 0x30;
constexpr size_t kTebClientIdProcess = 0x40;
constexpr size_t kTebClientIdThread = 0x48;
constexpr size_t kTebPeb = 0x60;

alignas(64) uint8_t g_fakePeb[0x1000];
alignas(64) thread_local uint8_t t_teb[kTebSize];
thread_local bool t_tebReady = false;

void PutPtr(size_t off, uint64_t value)
{
    memcpy(t_teb + off, &value, sizeof(value));
}

void InitThreadTeb()
{
    memset(t_teb, 0, sizeof(t_teb));
    uint64_t stackBase = 0;
    uint64_t stackLimit = 0;
    pthread_attr_t attr;
    if (pthread_getattr_np(pthread_self(), &attr) == 0) {
        void* addr = nullptr;
        size_t size = 0;
        if (pthread_attr_getstack(&attr, &addr, &size) == 0) {
            stackLimit = reinterpret_cast<uint64_t>(addr);
            stackBase = stackLimit + size;
        }
        pthread_attr_destroy(&attr);
    }
    if (stackBase == 0) {
        // Fallback: a unique, non-null per-thread value (used as fiber/thread id).
        stackBase = reinterpret_cast<uint64_t>(t_teb) + kTebSize;
    }
    PutPtr(0x00, ~0ULL); // ExceptionList: end of chain
    PutPtr(kTebStackBase, stackBase);
    PutPtr(kTebStackLimit, stackLimit);
    PutPtr(kTebSelf, reinterpret_cast<uint64_t>(t_teb));
    PutPtr(kTebClientIdProcess, static_cast<uint64_t>(getpid()));
    PutPtr(kTebClientIdThread, static_cast<uint64_t>(syscall(__NR_gettid)));
    PutPtr(kTebPeb, reinterpret_cast<uint64_t>(g_fakePeb));
    t_tebReady = true;
}
} // namespace

WindowsLibrary::WindowsLibrary(MappedMemory&& mapping, std::unordered_map<std::string, void*>&& exports, tEntryPoint entryPoint) :
    m_mapping(std::move(mapping)),
    m_exports(std::move(exports)),
    m_entryPoint(entryPoint)
{

}

WindowsLibrary::~WindowsLibrary()
{
    if (m_mapping.ptr() != nullptr && m_entryPoint != nullptr) {
        SetupCall();
        m_entryPoint(m_mapping, DLL_PROCESS_DETACH, nullptr);
    }
}

void* WindowsLibrary::GetExport(const std::string& exportName) const
{
    auto it = m_exports.find(exportName);
    return it == m_exports.end() ? nullptr : it->second;
}

void* WindowsLibrary::GetBaseAddress()
{
    return m_mapping;
}

void WindowsLibrary::SetupCall()
{
    if (!t_tebReady) {
        InitThreadTeb();
    }
    syscall(__NR_arch_prctl, ARCH_SET_GS, (void*)t_teb);
}

using ParsedPeRef = std::unique_ptr<peparse::parsed_pe, void (*)(peparse::parsed_pe*)>;

namespace {

ParsedPeRef ParseImage(const uint8_t* image, size_t size)
{
    if (image == nullptr || size == 0 || size > UINT32_MAX) {
        throw LoaderError(LINOODLE_E_PE_INVALID, "PE image size out of range");
    }
    // ParsePEFromPointer wraps the caller's buffer without copying or
    // re-reading the file and hands it to ParsePEFromBuffer.
    ParsedPeRef pe(peparse::ParsePEFromPointer(const_cast<uint8_t*>(image), static_cast<uint32_t>(size)),
                   peparse::DestructParsedPE);
    if (!pe) {
        throw LoaderError(LINOODLE_E_PE_INVALID, "Failed to parse PE: " + peparse::GetPEErrString());
    }
    if (pe->peHeader.nt.FileHeader.Machine != peparse::IMAGE_FILE_MACHINE_AMD64 ||
        pe->peHeader.nt.OptionalMagic != peparse::NT_OPTIONAL_64_MAGIC) {
        throw LoaderError(LINOODLE_E_PE_INVALID, "PE is not an AMD64 PE32+ image");
    }
    return pe;
}

bool RangeInImage(uint64_t rva, uint64_t len, uint64_t imageSize)
{
    return rva <= imageSize && len <= imageSize - rva;
}

void RelocateImage(const MappedMemory& imageMapping, const ParsedPeRef& pe)
{
    uint64_t delta = reinterpret_cast<uint64_t>(imageMapping.ptr()) - pe->peHeader.nt.OptionalHeader64.ImageBase;
    if (delta == 0) {
        return;
    }

    // Check that the PE is relocatable
    if (!(pe->peHeader.nt.OptionalHeader64.DllCharacteristics & peparse::IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)) {
        throw LoaderError(LINOODLE_E_PE_INVALID, "PE is not relocatable");
    }

    struct RelocContext {
        uint64_t delta;
        uint64_t imageBase;
        uint64_t imageSize;
        bool bad;
    };
    RelocContext ctx{ delta, pe->peHeader.nt.OptionalHeader64.ImageBase, imageMapping.size(), false };
    auto relocIt = [](void* pRawCtx, const peparse::VA& relocAddr, const peparse::reloc_type& type) -> int {
        RelocContext* pCtx = static_cast<RelocContext*>(pRawCtx);
        if (type == peparse::RELOC_ABSOLUTE) {
            return 0;
        }
        if (type != peparse::RELOC_DIR64 || relocAddr < pCtx->imageBase ||
            !RangeInImage(relocAddr - pCtx->imageBase, 8, pCtx->imageSize)) {
            pCtx->bad = true;
            return 1;
        }
        uint64_t* pData = reinterpret_cast<uint64_t*>(relocAddr + pCtx->delta);
        *pData += pCtx->delta;
        return 0;
    };

    peparse::IterRelocs(pe.get(), relocIt, &ctx);
    if (ctx.bad) {
        throw LoaderError(LINOODLE_E_PE_INVALID, "Unsupported or out-of-range relocation");
    }
}

PeTables CollectTables(const ParsedPeRef& pe)
{
    PeTables tables;
    auto importIt = [](void* raw, const peparse::VA&, const std::string& modName, const std::string& symName) -> int {
        static_cast<PeTables*>(raw)->imports.insert(WindowsAPI::NormalizeModule(modName) + "!" + symName);
        return 0;
    };
    peparse::IterImpVAString(pe.get(), importIt, &tables);
    auto exportIt = [](void* raw, const peparse::VA&, const std::string&, const std::string& func) -> int {
        static_cast<PeTables*>(raw)->exports.insert(func);
        return 0;
    };
    peparse::IterExpVA(pe.get(), exportIt, &tables);
    return tables;
}

} // namespace

PeTables WindowsLibrary::ReadTables(const uint8_t* image, size_t size)
{
    ParsedPeRef pe = ParseImage(image, size);
    return CollectTables(pe);
}

std::unique_ptr<WindowsLibrary> WindowsLibrary::LoadFromMemory(const uint8_t* image, size_t size)
{
    ParsedPeRef pe = ParseImage(image, size);
    const uint64_t imageBase = pe->peHeader.nt.OptionalHeader64.ImageBase;
    const uint64_t imageSize = pe->peHeader.nt.OptionalHeader64.SizeOfImage;
    if (imageSize == 0 || imageSize > (1ULL << 31)) {
        throw LoaderError(LINOODLE_E_PE_INVALID, "Invalid SizeOfImage");
    }

    // All imports must resolve before anything is mapped.
    {
        std::string missing;
        for (const auto& imp : CollectTables(pe).imports) {
            auto bang = imp.find('!');
            if (WindowsAPI::GetInstance().GetFunction(imp.substr(0, bang), imp.substr(bang + 1)) == nullptr) {
                missing += (missing.empty() ? "" : ", ") + imp;
            }
        }
        if (!missing.empty()) {
            throw LoaderError(LINOODLE_E_UNRESOLVED_IMPORT, "Unresolved imports (no shim): " + missing);
        }
    }

    void* rawImageMapping = mmap(nullptr, imageSize, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (rawImageMapping == MAP_FAILED) {
        throw LoaderError(LINOODLE_E_IO, "Failed to allocate memory for image");
    }
    MappedMemory imageMapping(rawImageMapping, imageSize);

    // Copy headers
    uint32_t headerSize = pe->peHeader.nt.OptionalHeader64.SizeOfHeaders;
    if (headerSize > imageMapping.size() || headerSize > size) {
        throw LoaderError(LINOODLE_E_PE_INVALID, "Invalid header size");
    }
    memcpy(imageMapping, image, headerSize);

    // Copy all the sections (bounds-checked)
    struct SecCtx {
        uint8_t* base;
        uint64_t imageSize;
        bool bad;
    };
    SecCtx secCtx{ static_cast<uint8_t*>(imageMapping), imageSize, false };
    auto sectionCopyIt = [](void* raw, const peparse::VA&, const std::string&, const peparse::image_section_header& s, const peparse::bounded_buffer* data) -> int {
        auto* c = static_cast<SecCtx*>(raw);
        uint64_t len = data == nullptr ? 0 : data->bufLen;
        uint64_t vsize = s.Misc.VirtualSize;
        if (len > vsize && vsize != 0) {
            len = vsize; // raw data beyond VirtualSize is file padding
        }
        if (!RangeInImage(s.VirtualAddress, len, c->imageSize) || !RangeInImage(s.VirtualAddress, vsize, c->imageSize)) {
            c->bad = true;
            return 1;
        }
        if (len != 0) {
            memcpy(c->base + s.VirtualAddress, data->buf, len);
        }
        return 0;
    };
    peparse::IterSec(pe.get(), sectionCopyIt, &secCtx);
    if (secCtx.bad) {
        throw LoaderError(LINOODLE_E_PE_INVALID, "Section outside SizeOfImage");
    }

    RelocateImage(imageMapping, pe);

    // Resolve imports (all were checked above; any failure here is fatal too)
    uint64_t delta = reinterpret_cast<uint64_t>(imageMapping.ptr()) - imageBase;
    struct ImpCtx {
        uint64_t delta;
        uint64_t imageBase;
        uint64_t imageSize;
        std::string bad;
    };
    ImpCtx impCtx{ delta, imageBase, imageSize, {} };
    auto importIt = [](void* raw, const peparse::VA& impAddr, const std::string& modName, const std::string& symName) -> int {
        auto* c = static_cast<ImpCtx*>(raw);
        void* func = WindowsAPI::GetInstance().GetFunction(modName, symName);
        if (func == nullptr || impAddr < c->imageBase || !RangeInImage(impAddr - c->imageBase, 8, c->imageSize)) {
            c->bad = modName + "!" + symName;
            return 1;
        }
        *reinterpret_cast<void**>(impAddr + c->delta) = func;
        return 0;
    };
    peparse::IterImpVAString(pe.get(), importIt, &impCtx);
    if (!impCtx.bad.empty()) {
        throw LoaderError(LINOODLE_E_UNRESOLVED_IMPORT, "Cannot bind import " + impCtx.bad);
    }

    // Headers read-only, then section permissions
    if (mprotect(imageMapping, headerSize, PROT_READ) == -1) {
        throw LoaderError(LINOODLE_E_IO, "Failed to mark header in image as read only");
    }
    bool permBad = false;
    auto sectionPermIt = [](void* raw, const peparse::VA&, const std::string&, const peparse::image_section_header& s, const peparse::bounded_buffer*) -> int {
        auto* c = static_cast<std::pair<uint8_t*, bool*>*>(raw);
        int prot = 0;
        if (s.Characteristics & peparse::IMAGE_SCN_MEM_EXECUTE)
            prot |= PROT_EXEC;
        if (s.Characteristics & peparse::IMAGE_SCN_MEM_WRITE)
            prot |= PROT_WRITE;
        if (s.Characteristics & peparse::IMAGE_SCN_MEM_READ)
            prot |= PROT_READ;
        if (s.Misc.VirtualSize != 0 && mprotect(c->first + s.VirtualAddress, s.Misc.VirtualSize, prot) == -1) {
            *c->second = true;
            return 1;
        }
        return 0;
    };
    std::pair<uint8_t*, bool*> permCtx{ static_cast<uint8_t*>(imageMapping), &permBad };
    peparse::IterSec(pe.get(), sectionPermIt, &permCtx);
    if (permBad) {
        throw LoaderError(LINOODLE_E_IO, "Failed to mprotect section");
    }

    // The allowed identities have no TLS directory (checked by the registry
    // import/export comparison and by this guard); SEH unwinding is not
    // supported, the SEH personality shims terminate the process.
    if (pe->peHeader.nt.OptionalHeader64.NumberOfRvaAndSizes > peparse::DIR_TLS &&
        pe->peHeader.nt.OptionalHeader64.DataDirectory[peparse::DIR_TLS].Size != 0) {
        throw LoaderError(LINOODLE_E_PE_INVALID, "PE TLS directory is not supported");
    }

    // Get addresses of exports
    struct ExportsContext {
        uint64_t delta;
        std::unordered_map<std::string, void*> exports;
    };
    ExportsContext ctx{ delta, {} };
    auto exportIt = [](void* rawCtx, const peparse::VA& funcAddr, const std::string&, const std::string& func) -> int {
        auto pCtx = static_cast<ExportsContext*>(rawCtx);
        pCtx->exports.emplace(func, reinterpret_cast<void*>(funcAddr + pCtx->delta));
        return 0;
    };
    peparse::IterExpVA(pe.get(), exportIt, &ctx);

    // Execute the entrypoint (CRT startup + DllMain)
    uint32_t entryRva = pe->peHeader.nt.OptionalHeader64.AddressOfEntryPoint;
    if (entryRva == 0 || !RangeInImage(entryRva, 1, imageSize)) {
        throw LoaderError(LINOODLE_E_PE_INVALID, "Invalid entry point");
    }
    SetupCall();
    WindowsAPI::GetInstance().SetModule(imageMapping.ptr());
    tEntryPoint entryPoint = reinterpret_cast<tEntryPoint>(static_cast<uint8_t*>(imageMapping) + entryRva);
    BOOL result = entryPoint(imageMapping, DLL_PROCESS_ATTACH, nullptr);
    if (!result) {
        WindowsAPI::GetInstance().SetModule(nullptr);
        throw LoaderError(LINOODLE_E_ENTRY_FAILED, "Library entry point returned FALSE");
    }

    return std::make_unique<WindowsLibrary>(std::move(imageMapping), std::move(ctx.exports), entryPoint);
}
