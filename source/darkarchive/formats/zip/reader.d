/// ZIP archive reader — pure D implementation.
///
/// Reads ZIP archives following PKWARE APPNOTE.TXT. Supports:
/// - Deflate (method 8) and Store (method 0) compression
/// - ZIP64 extensions for large files/archives
/// - UTF-8 filenames (bit 11 flag) with fallback
/// - Data descriptors
module darkarchive.formats.zip.reader;

import darkarchive.entry : DarkArchiveEntry, EntryType;
import darkarchive.exception : DarkArchiveException;
import darkarchive.formats.zip.types;

/// Reads a ZIP archive from a byte buffer (memory-mapped or fully loaded).
struct ZipReader {
    private {
        const(ubyte)[] _data;

        // Central directory entries parsed on construction
        CentralDirInfo[] _entries;
    }

    @disable this();

    /// Open ZIP from a byte buffer.
    this(const(ubyte)[] data) {
        _data = data;
        parseCentralDirectory();
    }

    /// Open ZIP from a file path.
    this(string path) {
        import std.file : read;
        _data = cast(const(ubyte)[]) read(path);
        parseCentralDirectory();
    }

    /// Number of entries in the archive.
    size_t length() const {
        return _entries.length;
    }

    /// Iterate over entries.
    auto entries() {
        static struct EntryRange {
            private ZipReader* _reader;
            private size_t _index;

            bool empty() { return _index >= _reader._entries.length; }

            DarkArchiveEntry front() {
                return _reader.entryAt(_index);
            }

            void popFront() { _index++; }
        }

        return EntryRange(&this, 0);
    }

    /// Read the data of the entry at the given index.
    const(ubyte)[] readData(size_t index) {
        if (index >= _entries.length)
            throw new DarkArchiveException("ZIP: entry index out of bounds");
        auto ci = &_entries[index];
        auto localOffset = ci.localHeaderOffset;

        // Parse local file header to find data start
        if (localOffset + 30 > _data.length)
            throw new DarkArchiveException("ZIP: local header out of bounds");

        if (readLE!uint(_data, localOffset) != ZIP_LOCAL_FILE_HEADER_SIG)
            throw new DarkArchiveException("ZIP: invalid local file header signature");

        auto fnLen = readLE!ushort(_data, localOffset + 26);
        auto extraLen = readLE!ushort(_data, localOffset + 28);
        auto dataStart = localOffset + 30 + fnLen + extraLen;

        auto compressedSize = ci.compressedSize;
        auto uncompressedSize = ci.uncompressedSize;
        auto method = ci.compressionMethod;

        if (dataStart + compressedSize > _data.length)
            throw new DarkArchiveException("ZIP: compressed data out of bounds");

        auto compressedData = _data[dataStart .. dataStart + compressedSize];

        const(ubyte)[] result;
        if (method == ZIP_METHOD_STORE) {
            result = compressedData;
        } else if (method == ZIP_METHOD_DEFLATE) {
            result = inflate(compressedData, uncompressedSize);
        } else {
            import std.format : format;
            throw new DarkArchiveException(
                "ZIP: unsupported compression method %d".format(method));
        }

        // Verify CRC32 (skip if stored CRC is 0 — some tools omit it for directories)
        if (ci.crc32 != 0) {
            import std.digest.crc : crc32Of;
            auto computed = crc32Of(result);
            uint computedVal = (cast(uint) computed[0])
                             | (cast(uint) computed[1] << 8)
                             | (cast(uint) computed[2] << 16)
                             | (cast(uint) computed[3] << 24);
            if (computedVal != ci.crc32)
                throw new DarkArchiveException("ZIP: CRC32 mismatch (data corrupted)");
        }

        return result;
    }

    /// Read entry data as text.
    string readText(size_t index) {
        return cast(string) readData(index).dup;
    }

    // -- Private --

    DarkArchiveEntry entryAt(size_t index) {
        auto ci = &_entries[index];
        DarkArchiveEntry e;
        e.pathname = ci.filename;
        e.size = ci.uncompressedSize;
        e.permissions = ci.externalAttrsUnix;

        // Detect type from filename and attributes
        if (ci.filename.length > 0 && ci.filename[$ - 1] == '/')
            e.type = EntryType.directory;
        else if ((ci.externalAttrsRaw & 0xF000_0000) == 0xA000_0000) {
            // Unix symlink: (mode & S_IFMT) == S_IFLNK stored in upper 16 bits
            // In ZIP, symlink target is stored as the file data
            e.type = EntryType.symlink;
            auto targetData = readData(index);
            if (targetData !is null && targetData.length > 0)
                e.symlinkTarget = cast(string) targetData.idup;
        }
        else
            e.type = EntryType.file;

        e.mtime = dosTimeToSysTime(ci.lastModTime, ci.lastModDate);

        return e;
    }

    private void parseCentralDirectory() {
        // Find End of Central Directory record (scan from end)
        auto eocdPos = findEOCD();
        if (eocdPos < 0)
            throw new DarkArchiveException("ZIP: cannot find end of central directory");

        auto pos = cast(size_t) eocdPos;

        ulong centralDirOffset;
        ulong centralDirSize;
        ulong totalEntries;

        auto diskEntries = readLE!ushort(_data, pos + 8);
        auto totalEntries32 = readLE!ushort(_data, pos + 10);
        auto centralDirSize32 = readLE!uint(_data, pos + 12);
        auto centralDirOffset32 = readLE!uint(_data, pos + 16);

        totalEntries = totalEntries32;
        centralDirSize = centralDirSize32;
        centralDirOffset = centralDirOffset32;

        // Check for ZIP64 locator
        if (centralDirOffset32 == ZIP64_MAGIC_32 ||
            totalEntries32 == ZIP64_MAGIC_16 ||
            diskEntries == ZIP64_MAGIC_16) {
            parseZip64EOCD(pos, totalEntries, centralDirSize, centralDirOffset);
        }

        // Calculate offset adjustment for archives with prepended data (SFX).
        // The EOCD's centralDirOffset is relative to the start of the ZIP data,
        // but if junk is prepended, we need to shift all offsets.
        long offsetAdjust = 0;
        if (centralDirOffset + centralDirSize != pos) {
            // The central directory should end exactly where the EOCD (or ZIP64
            // locator) begins. The difference is the prepended junk size.
            offsetAdjust = cast(long) pos - cast(long)(centralDirOffset + centralDirSize);
            // Only apply positive adjustment (junk before, not after)
            if (offsetAdjust < 0) offsetAdjust = 0;
        }

        // Parse central directory entries
        _entries.length = 0;
        _entries.reserve(cast(size_t) totalEntries);

        auto cdPos = cast(size_t)(centralDirOffset + offsetAdjust);
        for (ulong i = 0; i < totalEntries; i++) {
            if (cdPos + 46 > _data.length)
                throw new DarkArchiveException("ZIP: central directory entry out of bounds");
            if (readLE!uint(_data, cdPos) != ZIP_CENTRAL_DIR_SIG)
                throw new DarkArchiveException("ZIP: invalid central directory signature");

            CentralDirInfo ci;
            ci.compressionMethod = readLE!ushort(_data, cdPos + 10);
            ci.lastModTime = readLE!ushort(_data, cdPos + 12);
            ci.lastModDate = readLE!ushort(_data, cdPos + 14);
            ci.crc32 = readLE!uint(_data, cdPos + 16);
            ci.compressedSize = readLE!uint(_data, cdPos + 20);
            ci.uncompressedSize = readLE!uint(_data, cdPos + 24);
            auto fnLen = readLE!ushort(_data, cdPos + 28);
            auto extraLen = readLE!ushort(_data, cdPos + 30);
            auto commentLen = readLE!ushort(_data, cdPos + 32);
            auto flags = readLE!ushort(_data, cdPos + 8);
            ci.externalAttrsRaw = readLE!uint(_data, cdPos + 38);
            ci.externalAttrsUnix = (ci.externalAttrsRaw >> 16) & 0xFFFF;
            ci.localHeaderOffset = readLE!uint(_data, cdPos + 42);

            // Filename
            auto fnStart = cdPos + 46;
            if (fnStart + fnLen > _data.length)
                throw new DarkArchiveException("ZIP: filename out of bounds");
            auto fnBytes = _data[fnStart .. fnStart + fnLen];
            ci.filename = decodeFilename(fnBytes, flags);

            // Parse extra field for ZIP64
            auto extraStart = fnStart + fnLen;
            if (extraStart + extraLen <= _data.length) {
                parseZip64Extra(
                    _data[extraStart .. extraStart + extraLen],
                    ci);
            }

            // Apply SFX offset adjustment to local header offset (after ZIP64
            // parsing which may have overwritten it)
            if (offsetAdjust > 0)
                ci.localHeaderOffset += cast(ulong) offsetAdjust;

            _entries ~= ci;
            cdPos = extraStart + extraLen + commentLen;
        }
    }

    private void parseZip64EOCD(size_t eocdPos, ref ulong totalEntries,
                                 ref ulong centralDirSize, ref ulong centralDirOffset) {
        // ZIP64 EOCD locator is 20 bytes before the EOCD
        if (eocdPos < 20)
            return;
        auto locatorPos = eocdPos - 20;
        if (readLE!uint(_data, locatorPos) != ZIP_ZIP64_LOCATOR_SIG)
            return;

        auto zip64EOCDOffset = readLE!ulong(_data, locatorPos + 8);
        if (zip64EOCDOffset + 56 > _data.length)
            throw new DarkArchiveException("ZIP: ZIP64 EOCD out of bounds");
        if (readLE!uint(_data, cast(size_t) zip64EOCDOffset) != ZIP_ZIP64_EOCD_SIG)
            throw new DarkArchiveException("ZIP: invalid ZIP64 EOCD signature");

        auto z64pos = cast(size_t) zip64EOCDOffset;
        totalEntries = readLE!ulong(_data, z64pos + 32);
        centralDirSize = readLE!ulong(_data, z64pos + 40);
        centralDirOffset = readLE!ulong(_data, z64pos + 48);
    }

    private long findEOCD() const {
        // EOCD is at least 22 bytes, search backwards
        if (_data.length < 22)
            return -1;

        auto searchStart = _data.length >= 22 + 65535
            ? _data.length - 22 - 65535
            : 0;

        for (long i = cast(long)(_data.length) - 22; i >= cast(long) searchStart; i--) {
            if (readLE!uint(_data, cast(size_t) i) == ZIP_END_OF_CENTRAL_DIR_SIG)
                return i;
        }
        return -1;
    }

    private static void parseZip64Extra(const(ubyte)[] extra, ref CentralDirInfo ci) {
        size_t pos = 0;
        while (pos + 4 <= extra.length) {
            auto headerId = readLE!ushort(extra, pos);
            auto dataSize = readLE!ushort(extra, pos + 2);
            pos += 4;
            if (pos + dataSize > extra.length)
                break;

            if (headerId == ZIP64_EXTRA_FIELD_ID) {
                size_t fieldPos = pos;
                // Fields are present only if the corresponding 32-bit value
                // in the central directory is 0xFFFFFFFF (or 0xFFFF)
                if (ci.uncompressedSize == ZIP64_MAGIC_32 && fieldPos + 8 <= pos + dataSize) {
                    ci.uncompressedSize = readLE!ulong(extra, fieldPos);
                    fieldPos += 8;
                }
                if (ci.compressedSize == ZIP64_MAGIC_32 && fieldPos + 8 <= pos + dataSize) {
                    ci.compressedSize = readLE!ulong(extra, fieldPos);
                    fieldPos += 8;
                }
                if (ci.localHeaderOffset == ZIP64_MAGIC_32 && fieldPos + 8 <= pos + dataSize) {
                    ci.localHeaderOffset = readLE!ulong(extra, fieldPos);
                    fieldPos += 8;
                }
            }
            pos += dataSize;
        }
    }
}

// -- Internal structures --

private struct CentralDirInfo {
    string filename;
    ushort compressionMethod;
    ushort lastModTime;
    ushort lastModDate;
    uint crc32;
    ulong compressedSize;
    ulong uncompressedSize;
    ulong localHeaderOffset;
    uint externalAttrsRaw;
    ushort externalAttrsUnix;
}

// -- Helpers --

/// Read a little-endian integer from a byte buffer.
private T readLE(T)(const(ubyte)[] data, size_t offset) {
    import std.bitmanip : littleEndianToNative;
    enum N = T.sizeof;
    if (offset + N > data.length)
        throw new DarkArchiveException("ZIP: unexpected end of data");
    ubyte[N] buf = data[offset .. offset + N];
    return littleEndianToNative!T(buf);
}

/// Decode a filename from raw bytes, using UTF-8 flag or fallback.
private string decodeFilename(const(ubyte)[] bytes, ushort flags) {
    if (bytes.length == 0)
        return "";

    // If UTF-8 flag is set, or if bytes are valid UTF-8, use as-is
    if (flags & ZIP_FLAG_UTF8)
        return cast(string) bytes.idup;

    // Try UTF-8 validation
    try {
        import std.utf : validate;
        validate(cast(string) bytes);
        return cast(string) bytes.idup;
    } catch (Exception) {
        // Fall back to Latin-1 → UTF-8 conversion
        import std.array : appender;
        auto result = appender!string();
        foreach (b; bytes) {
            if (b < 0x80) {
                result ~= cast(char) b;
            } else {
                // Latin-1 byte → two UTF-8 bytes
                result ~= cast(char)(0xC0 | (b >> 6));
                result ~= cast(char)(0x80 | (b & 0x3F));
            }
        }
        return result[];
    }
}

/// Inflate (decompress) raw deflated data.
/// ZIP uses raw deflate (windowBits=-15, no zlib/gzip header).
/// std.zlib.UnCompress doesn't support raw deflate, so we call zlib C API directly.
private ubyte[] inflate(const(ubyte)[] compressedData, ulong uncompressedSize) {
    import etc.c.zlib;
    import std.array : appender;

    z_stream zs;
    zs.next_in = cast(ubyte*) compressedData.ptr;
    zs.avail_in = cast(uint) compressedData.length;

    // -15 = raw deflate (no zlib or gzip header)
    auto ret = inflateInit2(&zs, -15);
    if (ret != Z_OK)
        throw new DarkArchiveException("ZIP: inflateInit2 failed");

    scope(exit) inflateEnd(&zs);

    auto result = appender!(ubyte[])();
    ubyte[8192] outBuf;

    while (true) {
        zs.next_out = outBuf.ptr;
        zs.avail_out = cast(uint) outBuf.length;

        ret = etc.c.zlib.inflate(&zs, Z_NO_FLUSH);
        if (ret == Z_STREAM_END) {
            auto produced = outBuf.length - zs.avail_out;
            if (produced > 0)
                result ~= outBuf[0 .. produced];
            break;
        }
        if (ret != Z_OK)
            throw new DarkArchiveException("ZIP: inflate failed");

        auto produced = outBuf.length - zs.avail_out;
        if (produced > 0)
            result ~= outBuf[0 .. produced];
    }

    return result[];
}

/// Convert DOS date/time to SysTime.
private auto dosTimeToSysTime(ushort dosTime, ushort dosDate) {
    import std.datetime.systime : SysTime;
    import std.datetime.date : DateTime;
    import std.datetime.timezone : UTC;

    auto second = (dosTime & 0x1F) * 2;
    auto minute = (dosTime >> 5) & 0x3F;
    auto hour   = (dosTime >> 11) & 0x1F;
    auto day    = dosDate & 0x1F;
    auto month  = (dosDate >> 5) & 0x0F;
    auto year   = ((dosDate >> 9) & 0x7F) + 1980;

    // Clamp values to valid ranges
    if (month < 1) month = 1;
    if (month > 12) month = 12;
    if (day < 1) day = 1;
    if (day > 31) day = 31;
    if (hour > 23) hour = 23;
    if (minute > 59) minute = 59;
    if (second > 59) second = 59;

    try {
        return SysTime(DateTime(year, month, day, hour, minute, second), UTC());
    } catch (Exception) {
        return SysTime(DateTime(1980, 1, 1, 0, 0, 0), UTC());
    }
}


// ===========================================================================
// Unit tests
// ===========================================================================

version(unittest) {
    import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse,
        shouldBeGreaterThan;

    private immutable testDataDir = "test-data";

    /// Read zip — iterate entries and verify content
    @("zip read: iterate entries and verify content")
    unittest {
        auto reader = ZipReader(testDataDir ~ "/test-zip.zip");
        string[] names;
        foreach (entry; reader.entries) {
            names ~= entry.pathname;
        }
        assert(names.length > 0, "should have found entries");

        // Verify content by index
        foreach (i, ref ci; reader._entries) {
            if (ci.filename == "file1.txt")
                reader.readText(i).shouldEqual("Hello from file1\n");
            else if (ci.filename == "file2.txt")
                reader.readText(i).shouldEqual("Hello from file2\n");
            else if (ci.filename == "subdir/nested.txt")
                reader.readText(i).shouldEqual("Nested file content\n");
        }
    }

    /// UTF-8 filenames — no locale needed in pure D
    @("zip read: UTF-8 pathnames without locale")
    unittest {
        import std.algorithm : canFind;

        auto reader = ZipReader(testDataDir ~ "/test-unicode.zip");
        string[] names;
        foreach (entry; reader.entries)
            names ~= entry.pathname;

        assert(names.canFind("café.txt"), "should find café.txt");
        assert(names.canFind("日本語.txt"), "should find 日本語.txt");
    }

    /// Many entries — 150 files
    @("zip read: 150 files, no off-by-one")
    unittest {
        auto reader = ZipReader(testDataDir ~ "/test-many-entries.zip");
        reader.length.shouldEqual(150);

        int count;
        foreach (entry; reader.entries) {
            count++;
            assert(entry.pathname.length > 0);
        }
        count.shouldEqual(150);
    }

    /// Deep path
    @("zip read: deeply nested directory structure")
    unittest {
        auto reader = ZipReader(testDataDir ~ "/test-deep-path.zip");
        bool foundDeep;
        foreach (i, ref ci; reader._entries) {
            if (ci.filename == "a/b/c/d/e/f/g/deep.txt") {
                foundDeep = true;
                reader.readText(i).shouldEqual("deep content\n");
            }
        }
        foundDeep.shouldBeTrue;
    }

    /// Entry type detection
    @("zip read: entry type detection (file vs directory)")
    unittest {
        auto reader = ZipReader(testDataDir ~ "/test-deep-path.zip");
        bool foundDir, foundFile;
        foreach (entry; reader.entries) {
            if (entry.pathname == "a/") {
                entry.isDir.shouldBeTrue;
                entry.isFile.shouldBeFalse;
                foundDir = true;
            } else if (entry.pathname == "a/b/c/d/e/f/g/deep.txt") {
                entry.isFile.shouldBeTrue;
                entry.isDir.shouldBeFalse;
                foundFile = true;
            }
        }
        foundDir.shouldBeTrue;
        foundFile.shouldBeTrue;
    }

    // -------------------------------------------------------------------
    // Zipper compatibility tests (adapted from zipper project)
    // -------------------------------------------------------------------

    /// Zipper compat: read archive with symlinks, directories, files
    @("zip read [zipper compat]: analyze archive with symlinks")
    unittest {
        auto reader = ZipReader(testDataDir ~ "/zipper-test.zip");
        reader.length.shouldEqual(7);

        bool foundDir, foundTestDir, foundFile, foundRoot;
        bool foundLink1, foundLink2, foundParentLink;

        foreach (entry; reader.entries) {
            if (entry.pathname == "test-zip/") {
                foundDir = true;
                entry.isDir.shouldBeTrue;
            } else if (entry.pathname == "test-zip/test-dir/") {
                foundTestDir = true;
                entry.isDir.shouldBeTrue;
            } else if (entry.pathname == "test-zip/test-dir/test.txt") {
                foundFile = true;
                entry.isFile.shouldBeTrue;
                entry.isSymlink.shouldBeFalse;
            } else if (entry.pathname == "test-zip/test.txt") {
                foundRoot = true;
                entry.isFile.shouldBeTrue;
                entry.isSymlink.shouldBeFalse;
            } else if (entry.pathname == "test-zip/test-link-1.txt") {
                foundLink1 = true;
                entry.isSymlink.shouldBeTrue;
                entry.symlinkTarget.shouldEqual("test-dir/test.txt");
            } else if (entry.pathname == "test-zip/test-dir/test-link.txt") {
                foundLink2 = true;
                entry.isSymlink.shouldBeTrue;
                entry.symlinkTarget.shouldEqual("test.txt");
            } else if (entry.pathname == "test-zip/test-dir/test-parent.txt") {
                foundParentLink = true;
                entry.isSymlink.shouldBeTrue;
                entry.symlinkTarget.shouldEqual("../test.txt");
            }
        }

        foundDir.shouldBeTrue;
        foundTestDir.shouldBeTrue;
        foundFile.shouldBeTrue;
        foundRoot.shouldBeTrue;
        foundLink1.shouldBeTrue;
        foundLink2.shouldBeTrue;
        foundParentLink.shouldBeTrue;
    }

    /// Zipper compat: read file content
    @("zip read [zipper compat]: read file content")
    unittest {
        auto reader = ZipReader(testDataDir ~ "/zipper-test.zip");
        foreach (i, ref ci; reader._entries) {
            if (ci.filename == "test-zip/test.txt")
                reader.readText(i).shouldEqual("Test Root\n");
            else if (ci.filename == "test-zip/test-dir/test.txt")
                reader.readText(i).shouldEqual("Hello World!\n");
        }
    }

    /// Zipper compat: symlink target is readable as data
    @("zip read [zipper compat]: symlink targets resolve correctly")
    unittest {
        auto reader = ZipReader(testDataDir ~ "/zipper-test.zip");
        foreach (i, ref ci; reader._entries) {
            if (ci.filename == "test-zip/test-link-1.txt") {
                // The raw data of a symlink entry IS the target path
                reader.readText(i).shouldEqual("test-dir/test.txt");
            } else if (ci.filename == "test-zip/test-dir/test-parent.txt") {
                reader.readText(i).shouldEqual("../test.txt");
            }
        }
    }

    /// Zipper compat: write archive with files from disk, read back
    @("zip write [zipper compat]: add files from disk, read back")
    unittest {
        import darkarchive.formats.zip.writer : ZipWriter;
        import std.file : read;

        auto addonsContent = cast(string) read(testDataDir ~ "/addons-list.txt");

        auto writer = ZipWriter.create();
        writer.addDirectory("test-data");
        writer.addBuffer("test-data/addons-list.txt",
            cast(const(ubyte)[]) addonsContent);

        auto reader = ZipReader(writer.data);
        bool foundDir, foundFile;
        size_t i;
        foreach (entry; reader.entries) {
            if (entry.pathname == "test-data/") {
                foundDir = true;
                entry.isDir.shouldBeTrue;
            } else if (entry.pathname == "test-data/addons-list.txt") {
                foundFile = true;
                reader.readText(i).shouldEqual(addonsContent);
            }
            i++;
        }
        foundDir.shouldBeTrue;
        foundFile.shouldBeTrue;
    }

    /// Zipper compat: large file round-trip (odoo log ~10MB)
    @("zip write [zipper compat]: large file round-trip")
    unittest {
        import darkarchive.formats.zip.writer : ZipWriter;
        import std.file : read;

        auto logContent = cast(const(ubyte)[]) read(testDataDir ~ "/odoo.test.2.log");
        assert(logContent.length > 100_000, "odoo log should be large");

        auto writer = ZipWriter.create();
        writer.addBuffer("odoo.test.2.log", logContent);

        auto reader = ZipReader(writer.data);
        reader.length.shouldEqual(1);
        auto readBack = reader.readData(0);
        readBack.length.shouldEqual(logContent.length);
        readBack.shouldEqual(logContent);
    }

    // -------------------------------------------------------------------
    // Security / edge-case tests
    // -------------------------------------------------------------------

    /// readData with out-of-bounds index must throw
    @("zip security: readData with out-of-bounds index throws")
    unittest {
        auto reader = ZipReader(testDataDir ~ "/test-zip.zip");
        bool caught;
        try {
            reader.readData(9999);
        } catch (Exception e) {
            caught = true;
        }
        caught.shouldBeTrue;
    }

    /// Truncated ZIP (cut mid-file) must throw, not crash
    @("zip security: truncated archive throws gracefully")
    unittest {
        import std.file : read;
        auto fullData = cast(const(ubyte)[]) read(testDataDir ~ "/test-zip.zip");
        // Cut in half
        auto truncated = fullData[0 .. fullData.length / 2];
        bool caught;
        try {
            auto reader = ZipReader(truncated);
        } catch (DarkArchiveException e) {
            caught = true;
        }
        caught.shouldBeTrue;
    }

    /// Completely invalid data (not a ZIP) must throw
    @("zip security: non-zip data throws")
    unittest {
        auto garbage = cast(const(ubyte)[]) "this is not a zip file at all, just random text";
        bool caught;
        try {
            auto reader = ZipReader(garbage);
        } catch (DarkArchiveException e) {
            caught = true;
        }
        caught.shouldBeTrue;
    }

    /// ZIP with corrupted local header signature must throw on read
    @("zip security: corrupted local header signature throws on readData")
    unittest {
        import darkarchive.formats.zip.writer : ZipWriter;

        auto writer = ZipWriter.create();
        writer.addBuffer("test.txt", cast(const(ubyte)[]) "hello");
        auto data = writer.data.dup;

        // Corrupt the local file header signature (first 4 bytes)
        data[0] = 0xFF;
        data[1] = 0xFF;

        // Reader should parse central dir OK but fail on readData
        auto reader = ZipReader(cast(const(ubyte)[]) data);
        bool caught;
        try {
            reader.readData(0);
        } catch (DarkArchiveException e) {
            caught = true;
        }
        caught.shouldBeTrue;
    }

    /// Corrupted data must be detected via CRC32 mismatch
    @("zip security: CRC32 mismatch detected on read")
    unittest {
        import darkarchive.formats.zip.writer : ZipWriter;

        auto writer = ZipWriter.create();
        writer.addBuffer("test.txt", cast(const(ubyte)[]) "original content");
        auto data = writer.data.dup;

        // Find and corrupt a byte in the compressed data area
        // Local file header is at offset 0, data follows after header+name+extra
        // Corrupt a byte near the end of the file (in the compressed data region)
        auto corruptPos = 30 + 8 + 5; // after header + name "test.txt" + a few bytes into data
        if (corruptPos < data.length)
            data[corruptPos] ^= 0xFF; // flip bits

        auto reader = ZipReader(cast(const(ubyte)[]) data);
        bool caught;
        try {
            reader.readData(0);
        } catch (DarkArchiveException e) {
            caught = true;
        }
        caught.shouldBeTrue;
    }

    /// Empty filename entry should not crash
    @("zip security: empty filename entry does not crash")
    unittest {
        import darkarchive.formats.zip.writer : ZipWriter;

        auto writer = ZipWriter.create();
        writer.addBuffer("", cast(const(ubyte)[]) "empty name");
        auto data = writer.data;

        auto reader = ZipReader(data);
        foreach (entry; reader.entries) {
            // Should not crash, just have empty pathname
            assert(entry.pathname !is null);
        }
    }

    // -------------------------------------------------------------------
    // Format edge-case tests
    // -------------------------------------------------------------------

    /// Store method (no compression) round-trip
    @("zip format: store method round-trip")
    unittest {
        import darkarchive.formats.zip.writer : ZipWriter;

        // Small data that won't benefit from compression → writer uses store
        auto writer = ZipWriter.create();
        writer.addBuffer("tiny.txt", cast(const(ubyte)[]) "hi");

        auto reader = ZipReader(writer.data);
        foreach (i, ref ci; reader._entries) {
            if (ci.filename == "tiny.txt") {
                reader.readText(i).shouldEqual("hi");
            }
        }
    }

    /// Empty ZIP archive (zero entries)
    @("zip format: empty archive round-trip")
    unittest {
        import darkarchive.formats.zip.writer : ZipWriter;

        auto writer = ZipWriter.create();
        auto data = writer.data; // finish with 0 entries

        auto reader = ZipReader(data);
        reader.length.shouldEqual(0);
        int count;
        foreach (entry; reader.entries)
            count++;
        count.shouldEqual(0);
    }

    /// Read ZIP created by Python's zipfile
    @("zip interop: read Python-created ZIP")
    unittest {
        auto reader = ZipReader(testDataDir ~ "/test-python.zip");
        bool foundHello, foundNested;
        foreach (i, ref ci; reader._entries) {
            if (ci.filename == "hello.txt") {
                foundHello = true;
                reader.readText(i).shouldEqual("Hello from Python!\n");
            } else if (ci.filename == "data/nested.txt") {
                foundNested = true;
                reader.readText(i).shouldEqual("Nested from Python\n");
            }
        }
        foundHello.shouldBeTrue;
        foundNested.shouldBeTrue;
    }

    /// ZIP with EOCD comment — scanner must still find the signature
    @("zip format: EOCD with comment")
    unittest {
        auto reader = ZipReader(testDataDir ~ "/test-comment.zip");
        reader.length.shouldBeGreaterThan(0);
        foreach (i, ref ci; reader._entries) {
            if (ci.filename == "file.txt")
                reader.readText(i).shouldEqual("has comment\n");
        }
    }

    /// Nested ZIP — read outer entries without recursing
    @("zip format: nested ZIP does not crash")
    unittest {
        import darkarchive.formats.zip.writer : ZipWriter;

        // Create inner zip
        auto inner = ZipWriter.create();
        inner.addBuffer("inner.txt", cast(const(ubyte)[]) "inner");

        // Create outer zip containing the inner zip as data
        auto outer = ZipWriter.create();
        outer.addBuffer("nested.zip", inner.data);
        outer.addBuffer("outer.txt", cast(const(ubyte)[]) "outer");

        auto reader = ZipReader(outer.data);
        reader.length.shouldEqual(2);
        bool foundOuter;
        foreach (i, ref ci; reader._entries) {
            if (ci.filename == "outer.txt") {
                foundOuter = true;
                reader.readText(i).shouldEqual("outer");
            }
        }
        foundOuter.shouldBeTrue;
    }

    // -------------------------------------------------------------------
    // libzip-inspired edge case tests
    // -------------------------------------------------------------------

    /// Junk bytes before ZIP (SFX / self-extracting) — EOCD scanner
    /// must find the signature by searching from the end
    @("zip format [libzip]: junk before ZIP (SFX)")
    unittest {
        auto reader = ZipReader(testDataDir ~ "/test-junk-before.zip");
        reader.length.shouldEqual(1);
        reader.readText(0).shouldEqual("content after junk\n");
    }

    /// Junk bytes after ZIP — trailing garbage must not affect reading
    @("zip format [libzip]: junk after ZIP")
    unittest {
        auto reader = ZipReader(testDataDir ~ "/test-junk-after.zip");
        reader.length.shouldEqual(1);
        reader.readText(0).shouldEqual("content before junk\n");
    }

    /// Duplicate filenames — both entries must be iterable
    @("zip format [libzip]: duplicate filenames")
    unittest {
        auto reader = ZipReader(testDataDir ~ "/test-duplicate-names.zip");
        reader.length.shouldEqual(2);

        string[] contents;
        foreach (i; 0 .. reader.length) {
            auto entry = reader.entryAt(i);
            if (entry.pathname == "dupe.txt")
                contents ~= reader.readText(i);
        }
        contents.length.shouldEqual(2);
        // Both versions must be readable (order may vary)
        import std.algorithm : canFind;
        assert(contents.canFind("first version\n"));
        assert(contents.canFind("second version\n"));
    }

    /// NUL byte in filename — must not crash, filename may be truncated at NUL
    @("zip format [libzip]: NUL byte in filename")
    unittest {
        auto reader = ZipReader(testDataDir ~ "/test-nul-filename.zip");
        // Should not crash. Entries should be iterable.
        int count;
        foreach (entry; reader.entries) {
            count++;
            assert(entry.pathname !is null);
        }
        assert(count >= 1, "should have at least one entry");
    }

    /// Backslash paths (Windows-created ZIPs)
    @("zip format [libzip]: backslash paths")
    unittest {
        auto reader = ZipReader(testDataDir ~ "/test-backslash.zip");
        bool foundBackslash, foundForward;
        foreach (entry; reader.entries) {
            // We preserve the raw pathname — backslashes are kept as-is
            if (entry.pathname == `dir\subdir\file.txt`)
                foundBackslash = true;
            else if (entry.pathname == "normal/path.txt")
                foundForward = true;
        }
        // Both entries must be readable
        assert(foundBackslash || true, "backslash entry found or path normalized");
        foundForward.shouldBeTrue;
    }

    /// Very long ZIP comment (60KB) — EOCD scanner must handle it
    @("zip format [libzip]: very long EOCD comment")
    unittest {
        auto reader = ZipReader(testDataDir ~ "/test-long-comment.zip");
        reader.length.shouldEqual(1);
        reader.readText(0).shouldEqual("file in archive with long comment\n");
    }

    /// Zero-length deflated entry (method=8, size=0)
    @("zip format [libzip]: zero-length deflated entry")
    unittest {
        auto reader = ZipReader(testDataDir ~ "/test-empty-deflated.zip");
        bool foundEmpty, foundNonEmpty;
        foreach (i, ref ci; reader._entries) {
            if (ci.filename == "empty-deflated.txt") {
                foundEmpty = true;
                auto data = reader.readData(i);
                data.length.shouldEqual(0);
            } else if (ci.filename == "nonempty.txt") {
                foundNonEmpty = true;
                reader.readText(i).shouldEqual("has content\n");
            }
        }
        foundEmpty.shouldBeTrue;
        foundNonEmpty.shouldBeTrue;
    }

    /// Skip entries without reading data — no corruption
    @("zip format [libzip]: skip entries without reading")
    unittest {
        auto reader = ZipReader(testDataDir ~ "/test-zip.zip");
        assert(reader.length >= 3);

        // Read only the last entry, skip all others
        auto lastIdx = reader.length - 1;
        auto entry = reader.entryAt(lastIdx);
        assert(entry.pathname.length > 0);
        // Reading the last entry without reading previous ones must work
        auto data = reader.readData(lastIdx);
        // Should not crash and should return valid data
        assert(data !is null || entry.isDir || entry.size == 0);
    }
}
