// linoodle: SHA-256-pinned, handle-based loader for Oodle Windows DLLs.
// See linoodle.h for the contract. Rewritten by rearc patch 0002; the
// upstream global oo2core_8 loader (g_oodleWrapper) is removed.
#include "linoodle.h"
#include "windows_library.h"
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {

struct OodleIdentity {
    const char* sha256;
    unsigned long long size;
    const char* fileName;
    const char* abiProfile;
    const char* status;
    const char* const* imports;
    const char* const* exports;
    const char* const* requiredExports;
};

#include "linoodle_identities.inc"

// ------------------------------------------------------------ SHA-256 (FIPS 180-4)
class Sha256 {
public:
    Sha256() { Reset(); }
    void Update(const uint8_t* data, size_t len)
    {
        m_total += len;
        while (len > 0) {
            size_t take = std::min(len, sizeof(m_buf) - m_used);
            memcpy(m_buf + m_used, data, take);
            m_used += take;
            data += take;
            len -= take;
            if (m_used == sizeof(m_buf)) {
                Block(m_buf);
                m_used = 0;
            }
        }
    }
    std::string HexDigest()
    {
        uint64_t bits = m_total * 8;
        uint8_t pad = 0x80;
        Update(&pad, 1);
        uint8_t zero = 0;
        while (m_used != 56) {
            Update(&zero, 1);
        }
        uint8_t lenBytes[8];
        for (int i = 0; i < 8; i++) {
            lenBytes[i] = static_cast<uint8_t>(bits >> (56 - 8 * i));
        }
        Update(lenBytes, 8);
        static const char* hex = "0123456789abcdef";
        std::string out;
        for (uint32_t v : m_h) {
            for (int s = 28; s >= 0; s -= 4) {
                out.push_back(hex[(v >> s) & 0xF]);
            }
        }
        return out;
    }

private:
    static uint32_t Rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
    void Reset()
    {
        static const uint32_t init[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                          0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
        memcpy(m_h, init, sizeof(m_h));
        m_used = 0;
        m_total = 0;
    }
    void Block(const uint8_t* p)
    {
        static const uint32_t k[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };
        uint32_t w[64];
        for (int i = 0; i < 16; i++) {
            w[i] = (uint32_t(p[4 * i]) << 24) | (uint32_t(p[4 * i + 1]) << 16) | (uint32_t(p[4 * i + 2]) << 8) | p[4 * i + 3];
        }
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = Rotr(w[i - 15], 7) ^ Rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = Rotr(w[i - 2], 17) ^ Rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = m_h[0], b = m_h[1], c = m_h[2], d = m_h[3], e = m_h[4], f = m_h[5], g = m_h[6], h = m_h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t t1 = h + (Rotr(e, 6) ^ Rotr(e, 11) ^ Rotr(e, 25)) + ((e & f) ^ (~e & g)) + k[i] + w[i];
            uint32_t t2 = (Rotr(a, 2) ^ Rotr(a, 13) ^ Rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        m_h[0] += a; m_h[1] += b; m_h[2] += c; m_h[3] += d;
        m_h[4] += e; m_h[5] += f; m_h[6] += g; m_h[7] += h;
    }
    uint32_t m_h[8];
    uint8_t m_buf[64];
    size_t m_used;
    uint64_t m_total;
};

// ------------------------------------------------------------ ABI profile oo2core9-v1
typedef __attribute__((ms_abi)) size_t(*tDecompressFunc)(uint8_t* srcBuf, size_t srcLen, uint8_t* dstBuf, size_t dstLen, int64_t fuzz, int64_t crc, int64_t verbose, uint8_t* dstBase, size_t e, void* cb, void* cbCtx, void* scratch, size_t scratchSize, int64_t threadPhase);
typedef __attribute__((ms_abi)) size_t(*tCompressFunc)(int64_t codec, uint8_t* srcBuf, size_t srcLen, uint8_t* dstBuf, int64_t level, void* opts, size_t offs, size_t unused, void* scratch, size_t scratchSize);

typedef __attribute__((ms_abi)) const void*(*tGetDefaultFunc)(int32_t codec, int32_t level);

constexpr size_t kMaxDllBytes = 64u << 20;
constexpr size_t kMaxRequestBytes = size_t(1) << 31; // 2 GiB per call

struct Handle {
    std::string sha256;
    const OodleIdentity* identity = nullptr;
    std::unique_ptr<WindowsLibrary> lib;
    tCompressFunc compress = nullptr;
    tDecompressFunc decompress = nullptr;
    tGetDefaultFunc getDefault = nullptr;
};

std::mutex g_openLock;
std::atomic<Handle*> g_current{ nullptr };

void SetErr(char* err, size_t cap, int code, const std::string& msg)
{
    if (err != nullptr && cap > 0) {
        snprintf(err, cap, "E%d: %s", code, msg.c_str());
    }
}

std::vector<uint8_t> ReadWholeFile(const char* path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        throw LoaderError(LINOODLE_E_IO, std::string("cannot open DLL: ") + strerror(errno));
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        throw LoaderError(LINOODLE_E_IO, "DLL path is not a regular file");
    }
    if (st.st_size <= 0 || static_cast<uint64_t>(st.st_size) > kMaxDllBytes) {
        close(fd);
        throw LoaderError(LINOODLE_E_IO, "DLL size out of range");
    }
    std::vector<uint8_t> buf(static_cast<size_t>(st.st_size));
    size_t got = 0;
    while (got < buf.size()) {
        ssize_t n = read(fd, buf.data() + got, buf.size() - got);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            close(fd);
            throw LoaderError(LINOODLE_E_IO, "short read on DLL");
        }
        got += static_cast<size_t>(n);
    }
    // Reject a file that grew meanwhile; the hash covers exactly `buf`.
    uint8_t extra;
    ssize_t more = read(fd, &extra, 1);
    close(fd);
    if (more != 0) {
        throw LoaderError(LINOODLE_E_IO, "DLL changed while reading");
    }
    return buf;
}

std::string DiffSets(const std::set<std::string>& actual, const char* const* expected, const char* what)
{
    std::set<std::string> exp;
    for (const char* const* p = expected; *p != nullptr; ++p) {
        exp.insert(*p);
    }
    std::string missing, extra;
    for (const auto& e : exp) {
        if (!actual.count(e)) missing += " " + e;
    }
    for (const auto& a : actual) {
        if (!exp.count(a)) extra += " " + a;
    }
    if (missing.empty() && extra.empty()) {
        return "";
    }
    return std::string(what) + " differ; missing:" + (missing.empty() ? " none" : missing) +
           "; unexpected:" + (extra.empty() ? " none" : extra);
}

Handle* OpenImpl(const char* path, const char* expected)
{
    if (path == nullptr) {
        throw LoaderError(LINOODLE_E_INVALID_ARGUMENT, "path is NULL");
    }
    std::string want;
    if (expected != nullptr) {
        want = expected;
        std::transform(want.begin(), want.end(), want.begin(), [](unsigned char c) { return static_cast<char>(tolower(c)); });
        if (want.size() != 64 || want.find_first_not_of("0123456789abcdef") != std::string::npos) {
            throw LoaderError(LINOODLE_E_INVALID_ARGUMENT, "expected_sha256_hex must be 64 hex characters");
        }
    }

    std::vector<uint8_t> bytes = ReadWholeFile(path);
    Sha256 sha;
    sha.Update(bytes.data(), bytes.size());
    std::string actual = sha.HexDigest();
    if (!want.empty() && actual != want) {
        throw LoaderError(LINOODLE_E_HASH_MISMATCH, "DLL SHA-256 " + actual + " does not match requested " + want);
    }
    const OodleIdentity* id = nullptr;
    for (const auto& cand : k_identities) {
        if (actual == cand.sha256) {
            id = &cand;
        }
    }
    if (id == nullptr) {
        throw LoaderError(LINOODLE_E_UNKNOWN_IDENTITY, "DLL SHA-256 " + actual + " is not a registered Oodle identity");
    }
    const std::string idName = std::string(id->sha256).substr(0, 16) + " (" + id->fileName + ")";
    if (bytes.size() != id->size) {
        throw LoaderError(LINOODLE_E_IDENTITY_MISMATCH, "identity " + idName + ": size differs from registry");
    }
    if (strcmp(id->abiProfile, "oo2core9-v1") != 0) {
        throw LoaderError(LINOODLE_E_UNSUPPORTED_ABI, "identity " + idName + ": unsupported abi_profile " + id->abiProfile);
    }

    // Same in-memory bytes are parsed for the table check and for loading.
    PeTables tables = WindowsLibrary::ReadTables(bytes.data(), bytes.size());
    std::string d = DiffSets(tables.imports, id->imports, "import tables");
    if (d.empty()) {
        d = DiffSets(tables.exports, id->exports, "export tables");
    }
    if (!d.empty()) {
        throw LoaderError(LINOODLE_E_IDENTITY_MISMATCH, "identity " + idName + ": " + d);
    }
    for (const char* const* p = id->requiredExports; *p != nullptr; ++p) {
        if (!tables.exports.count(*p)) {
            throw LoaderError(LINOODLE_E_IDENTITY_MISMATCH, "identity " + idName + ": required export missing: " + *p);
        }
    }

    auto h = std::make_unique<Handle>();
    h->sha256 = actual;
    h->identity = id;
    h->lib = WindowsLibrary::LoadFromMemory(bytes.data(), bytes.size());
    h->compress = reinterpret_cast<tCompressFunc>(h->lib->GetExport("OodleLZ_Compress"));
    h->decompress = reinterpret_cast<tDecompressFunc>(h->lib->GetExport("OodleLZ_Decompress"));
    h->getDefault = reinterpret_cast<tGetDefaultFunc>(h->lib->GetExport("OodleLZ_CompressOptions_GetDefault"));
    if (h->compress == nullptr || h->decompress == nullptr || h->getDefault == nullptr) {
        throw LoaderError(LINOODLE_E_IDENTITY_MISMATCH, "identity " + idName + ": OodleLZ exports not resolvable");
    }
    return h.release();
}

Handle* AsHandle(void* h)
{
    Handle* cur = g_current.load();
    return (h != nullptr && h == cur) ? cur : nullptr;
}

// Conservative output bound: well above Oodle's documented per-256 KiB-chunk
// worst case, so the DLL never writes past our scratch buffer.
size_t CompressScratchBound(size_t n)
{
    return n + n / 2 + 274 * ((n + 0x3FFFF) / 0x40000) + 65536;
}

} // namespace

extern "C" void* linoodle_open(const char* path, const char* expected_sha256_hex, char* err, size_t err_cap)
{
    std::lock_guard<std::mutex> g(g_openLock);
    if (err != nullptr && err_cap > 0) {
        err[0] = 0;
    }
    if (g_current.load() != nullptr) {
        SetErr(err, err_cap, LINOODLE_E_BUSY, "an Oodle DLL is already open in this process");
        return nullptr;
    }
    try {
        Handle* h = OpenImpl(path, expected_sha256_hex);
        g_current.store(h);
        return h;
    }
    catch (const LoaderError& e) {
        SetErr(err, err_cap, e.code(), e.what());
    }
    catch (const std::exception& e) {
        SetErr(err, err_cap, LINOODLE_E_PE_INVALID, e.what());
    }
    catch (...) {
        SetErr(err, err_cap, LINOODLE_E_PE_INVALID, "unknown loader failure");
    }
    WindowsAPI::GetInstance().SetModule(nullptr);
    return nullptr;
}

extern "C" int linoodle_identity(void* h, char sha256_hex_out[65])
{
    Handle* hd = AsHandle(h);
    if (hd == nullptr || sha256_hex_out == nullptr) {
        return -1;
    }
    memcpy(sha256_hex_out, hd->sha256.c_str(), 65);
    return 0;
}

extern "C" intptr_t linoodle_compress(void* h, int32_t compressor, int32_t level, const uint8_t* src, size_t src_len, uint8_t* dst, size_t dst_cap)
{
    Handle* hd = AsHandle(h);
    if (hd == nullptr || (src == nullptr && src_len != 0) || dst == nullptr || src_len == 0 || src_len > kMaxRequestBytes) {
        return -1;
    }
    std::vector<uint8_t> scratch;
    try {
        scratch.resize(CompressScratchBound(src_len));
    }
    catch (...) {
        return -3;
    }
    WindowsLibrary::SetupCall();
    size_t n = hd->compress(compressor, const_cast<uint8_t*>(src), src_len, scratch.data(), level, nullptr, 0, 0, nullptr, 0);
    if (n == 0 || n > scratch.size()) {
        return n == 0 ? 0 : -1;
    }
    if (n > dst_cap) {
        return -2;
    }
    memcpy(dst, scratch.data(), n);
    return static_cast<intptr_t>(n);
}

namespace {

// Validates and applies overrides to `block`. Returns false on any violation.
bool ApplyOverrides(uint8_t* block, const linoodle_compress_overrides* ov)
{
    if (ov == nullptr) {
        return true;
    }
    if (ov->count > LINOODLE_MAX_OVERRIDES) {
        return false;
    }
    bool used[LINOODLE_OPTIONS_BLOCK_LEN] = {};
    for (uint32_t i = 0; i < ov->count; i++) {
        const linoodle_override& o = ov->entries[i];
        if (o.size != 1 && o.size != 2 && o.size != 4 && o.size != 8) {
            return false;
        }
        if (o.offset % o.size != 0 || o.offset > LINOODLE_OPTIONS_BLOCK_LEN ||
            o.size > LINOODLE_OPTIONS_BLOCK_LEN - o.offset) {
            return false;
        }
        if (o.size < 8 && (o.value >> (8 * o.size)) != 0) {
            return false;
        }
        for (uint32_t b = 0; b < o.size; b++) {
            if (used[o.offset + b]) {
                return false;
            }
            used[o.offset + b] = true;
        }
    }
    for (uint32_t i = 0; i < ov->count; i++) {
        const linoodle_override& o = ov->entries[i];
        for (uint32_t b = 0; b < o.size; b++) {
            block[o.offset + b] = static_cast<uint8_t>(o.value >> (8 * b));
        }
    }
    return true;
}

} // namespace

extern "C" int linoodle_get_default_options(void* h, int32_t compressor, int32_t level, uint8_t out[LINOODLE_OPTIONS_BLOCK_LEN])
{
    Handle* hd = AsHandle(h);
    if (hd == nullptr || out == nullptr) {
        return -1;
    }
    WindowsLibrary::SetupCall();
    const void* p = hd->getDefault(compressor, level);
    if (p == nullptr) {
        return -4;
    }
    memcpy(out, p, LINOODLE_OPTIONS_BLOCK_LEN);
    return 0;
}

extern "C" intptr_t linoodle_compress_ex(void* h, int32_t compressor, int32_t level, const uint8_t* src, size_t src_len, uint8_t* dst, size_t dst_cap, const linoodle_compress_overrides* ov, size_t scratch_size)
{
    Handle* hd = AsHandle(h);
    if (hd == nullptr || (src == nullptr && src_len != 0) || dst == nullptr || src_len == 0 || src_len > kMaxRequestBytes) {
        return -1;
    }
    if (scratch_size > LINOODLE_MAX_SCRATCH) {
        return -6;
    }
    uint8_t opts[LINOODLE_OPTIONS_BLOCK_LEN];
    int rc = linoodle_get_default_options(h, compressor, level, opts);
    if (rc != 0) {
        return rc;
    }
    if (!ApplyOverrides(opts, ov)) {
        return -5;
    }
    std::vector<uint8_t> out;
    std::vector<uint8_t> scratch;
    try {
        out.resize(CompressScratchBound(src_len));
        scratch.resize(scratch_size);
    }
    catch (...) {
        return -3;
    }
    WindowsLibrary::SetupCall();
    size_t n = hd->compress(compressor, const_cast<uint8_t*>(src), src_len, out.data(), level, opts, 0, 0,
                            scratch_size != 0 ? scratch.data() : nullptr, scratch_size);
    if (n == 0 || n > out.size()) {
        return n == 0 ? 0 : -1;
    }
    if (n > dst_cap) {
        return -2;
    }
    memcpy(dst, out.data(), n);
    return static_cast<intptr_t>(n);
}

extern "C" intptr_t linoodle_decompress(void* h, const uint8_t* src, size_t src_len, uint8_t* dst, size_t dst_len)
{
    Handle* hd = AsHandle(h);
    if (hd == nullptr || src == nullptr || dst == nullptr || src_len == 0 || dst_len == 0 ||
        src_len > kMaxRequestBytes || dst_len > kMaxRequestBytes) {
        return -1;
    }
    WindowsLibrary::SetupCall();
    // fuzz=1 (fuzz-safe), crc=0, verbose=0, no dictionary base, no callback,
    // no scratch, threadPhase=3 (unthreaded: both phases).
    size_t n = hd->decompress(const_cast<uint8_t*>(src), src_len, dst, dst_len, 1, 0, 0, nullptr, 0, nullptr, nullptr, nullptr, 0, 3);
    if (n != dst_len) {
        return -1;
    }
    return static_cast<intptr_t>(n);
}

extern "C" void linoodle_close(void* h)
{
    std::lock_guard<std::mutex> g(g_openLock);
    Handle* hd = AsHandle(h);
    if (hd == nullptr) {
        return;
    }
    g_current.store(nullptr);
    delete hd; // ~WindowsLibrary runs DllMain(PROCESS_DETACH) and unmaps
    WindowsAPI::GetInstance().SetModule(nullptr);
}

extern "C" size_t OodleLZ_Decompress(uint8_t* srcBuf, size_t srcLen, uint8_t* dstBuf, size_t dstLen, int64_t fuzz, int64_t crc, int64_t verbose, uint8_t* dstBase, size_t e, void* cb, void* cbCtx, void* scratch, size_t scratchSize, int64_t threadPhase)
{
    Handle* hd = g_current.load();
    if (hd == nullptr) {
        return 0;
    }
    WindowsLibrary::SetupCall();
    return hd->decompress(srcBuf, srcLen, dstBuf, dstLen, fuzz, crc, verbose, dstBase, e, cb, cbCtx, scratch, scratchSize, threadPhase);
}

extern "C" size_t OodleLZ_Compress(int64_t codec, uint8_t* srcBuf, size_t srcLen, uint8_t* dstBuf, int64_t level, void* opts, size_t offs, size_t unused, void* scratch, size_t scratchSize)
{
    Handle* hd = g_current.load();
    if (hd == nullptr) {
        return 0;
    }
    WindowsLibrary::SetupCall();
    return hd->compress(codec, srcBuf, srcLen, dstBuf, level, opts, offs, unused, scratch, scratchSize);
}
