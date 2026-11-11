/* linoodle public C API (rearc patch 0002).
 *
 * Loads one SHA-256-pinned Oodle Windows DLL per process from an explicit
 * path. The file is read once into memory; SHA-256, size, machine and the
 * complete import/export tables of exactly those bytes are compared with the
 * compiled-in identity registry (linoodle_identities.inc, generated from
 * crates/oodle-linoodle/oodle-identities.json) before the same buffer is
 * parsed and mapped. Every import must resolve to a loader shim, otherwise
 * loading is refused. No DLL name is hardcoded and nothing is loaded
 * implicitly.
 *
 * Thread model: calls may come from any thread (each thread gets its own fake
 * TEB in gs). Only one DLL can be open per process at a time.
 */
#ifndef LINOODLE_H
#define LINOODLE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opens `path`. `expected_sha256_hex` (64 hex chars, case-insensitive) pins
 * the identity; NULL accepts any registered identity. Returns NULL on error
 * and writes a NUL-terminated message "E<code>: <text>" to `err` (if
 * err_cap > 0); <code> is a linoodle_status value. */
void* linoodle_open(const char* path, const char* expected_sha256_hex, char* err, size_t err_cap);

/* Writes the lowercase SHA-256 hex of the open DLL (+ NUL). 0 = ok, -1 = bad handle. */
int linoodle_identity(void* h, char sha256_hex_out[65]);

/* Compresses with OodleLZ_Compress(compressor, src, src_len, ..., level,
 * NULL options). Returns the compressed size, or <= 0 on error (-2 = output
 * would not fit into dst_cap, nothing written beyond dst_cap). */
intptr_t linoodle_compress(void* h, int32_t compressor, int32_t level, const uint8_t* src,
                           size_t src_len, uint8_t* dst, size_t dst_cap);

/* ---- rearc patch 0003: XTool-style compression with a modified default
 * options block. No Oodle struct field names are assumed: the options are an
 * opaque LINOODLE_OPTIONS_BLOCK_LEN-byte block obtained from the DLL's own
 * OodleLZ_CompressOptions_GetDefault(compressor, level) and modified only at
 * explicit byte offsets. */
#define LINOODLE_OPTIONS_BLOCK_LEN 0x58u
#define LINOODLE_MAX_OVERRIDES 8u
#define LINOODLE_MAX_SCRATCH ((size_t)256 << 20)

/* Writes `size` (1, 2, 4 or 8) little-endian bytes of `value` at byte
 * `offset` of the block. offset must be a multiple of size and
 * offset + size <= LINOODLE_OPTIONS_BLOCK_LEN; `value` must fit into size. */
typedef struct linoodle_override {
    uint32_t offset;
    uint32_t size;
    uint64_t value;
} linoodle_override;

typedef struct linoodle_compress_overrides {
    uint32_t count;                                   /* <= LINOODLE_MAX_OVERRIDES */
    linoodle_override entries[LINOODLE_MAX_OVERRIDES]; /* ranges must not overlap */
} linoodle_compress_overrides;

/* Copies the LINOODLE_OPTIONS_BLOCK_LEN bytes returned by
 * OodleLZ_CompressOptions_GetDefault(compressor, level) into `out`.
 * 0 = ok, -1 = bad argument/handle, -4 = GetDefault returned NULL. */
int linoodle_get_default_options(void* h, int32_t compressor, int32_t level,
                                 uint8_t out[LINOODLE_OPTIONS_BLOCK_LEN]);

/* Like linoodle_compress, but passes a copy of the GetDefault block (with
 * `ov` applied; NULL = unmodified) as the options pointer and a caller-sized
 * scratch buffer (0 = NULL scratch; <= LINOODLE_MAX_SCRATCH). Return values as
 * linoodle_compress; -5 = invalid overrides, -6 = scratch too large. */
intptr_t linoodle_compress_ex(void* h, int32_t compressor, int32_t level, const uint8_t* src,
                              size_t src_len, uint8_t* dst, size_t dst_cap,
                              const linoodle_compress_overrides* ov, size_t scratch_size);

/* Decompresses exactly dst_len bytes with OodleLZ_Decompress (fuzz-safe,
 * no CRC check, unthreaded). Returns the decoded size (== dst_len) or < 0. */
intptr_t linoodle_decompress(void* h, const uint8_t* src, size_t src_len, uint8_t* dst,
                             size_t dst_len);

/* Runs DllMain(PROCESS_DETACH) and unmaps the image. NULL is ignored. */
void linoodle_close(void* h);

enum linoodle_status {
    LINOODLE_OK = 0,
    LINOODLE_E_INVALID_ARGUMENT = 1,
    LINOODLE_E_IO = 2,
    LINOODLE_E_UNKNOWN_IDENTITY = 3,   /* SHA-256 not in the registry */
    LINOODLE_E_HASH_MISMATCH = 4,      /* differs from expected_sha256_hex */
    LINOODLE_E_IDENTITY_MISMATCH = 5,  /* size/import/export tables differ from registry */
    LINOODLE_E_PE_INVALID = 6,
    LINOODLE_E_UNRESOLVED_IMPORT = 7,  /* an import has no loader shim */
    LINOODLE_E_ENTRY_FAILED = 8,       /* DllMain(PROCESS_ATTACH) returned FALSE */
    LINOODLE_E_BUSY = 9,               /* another DLL is already open in this process */
    LINOODLE_E_UNSUPPORTED_ABI = 10
};

/* Upstream linoodle exports with unchanged signatures (abi_profile
 * "oo2core9-v1"). They forward to the currently open handle and return 0
 * when none is open; they never load a DLL by themselves. */
size_t OodleLZ_Decompress(uint8_t* srcBuf, size_t srcLen, uint8_t* dstBuf, size_t dstLen,
                          int64_t fuzz, int64_t crc, int64_t verbose, uint8_t* dstBase, size_t e,
                          void* cb, void* cbCtx, void* scratch, size_t scratchSize,
                          int64_t threadPhase);
size_t OodleLZ_Compress(int64_t codec, uint8_t* srcBuf, size_t srcLen, uint8_t* dstBuf,
                        int64_t level, void* opts, size_t offs, size_t unused, void* scratch,
                        size_t scratchSize);

#ifdef __cplusplus
}
#endif

#endif
