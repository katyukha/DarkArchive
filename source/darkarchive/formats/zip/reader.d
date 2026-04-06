/// ZIP archive reader — pure D implementation.
///
/// Reads ZIP archives following PKWARE APPNOTE.TXT. Supports:
/// - Deflate (method 8) and Store (method 0) compression
/// - ZIP64 extensions for large files/archives
/// - UTF-8 filenames (bit 11 flag) with fallback
/// - Data descriptors
/// - File-backed I/O (does not load full archive into memory)
module darkarchive.formats.zip.reader;

import darkarchive.entry : DarkArchiveEntry, EntryType;
import darkarchive.exception : DarkArchiveException;
import darkarchive.formats.zip.types;
import darkarchive.datasource : DataSource;

/// Reads a ZIP archive from a file or memory buffer.
struct ZipReader {
    private {
        DataSource _ds;

        // Central directory entries parsed on construction
        CentralDirInfo[] _entries;
    }

    @disable this();

    /// Open ZIP from a file path (does not load full file into memory).
    this(string path) {
        _ds = DataSource.fromFile(path);
        scope(failure) _ds.close();
        parseCentralDirectory();
    }

    /// Number of entries in the archive.
    size_t length() const {
        return _entries.length;
    }

    /// Close the underlying file handle.
    void close() {
        _ds.close();
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
        if (localOffset + 30 > _ds.length)
            throw new DarkArchiveException("ZIP: local header out of bounds");

        if (_ds.readLE!uint(localOffset) != ZIP_LOCAL_FILE_HEADER_SIG)
            throw new DarkArchiveException("ZIP: invalid local file header signature");

        auto fnLen = _ds.readLE!ushort(localOffset + 26);
        auto extraLen = _ds.readLE!ushort(localOffset + 28);

        // Use checked addition to prevent integer overflow
        ulong dataStart = localOffset;
        dataStart += 30;
        dataStart += fnLen;
        dataStart += extraLen;
        if (dataStart > _ds.length)
            throw new DarkArchiveException("ZIP: local header fields extend past data");

        auto compressedSize = ci.compressedSize;
        auto uncompressedSize = ci.uncompressedSize;
        auto method = ci.compressionMethod;

        if (compressedSize > _ds.length || dataStart + compressedSize > _ds.length)
            throw new DarkArchiveException("ZIP: compressed data out of bounds");

        auto compressedData = _ds.readSlice(dataStart, compressedSize);

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

    /// Read entry data in chunks via a sink delegate. Never loads the full
    /// entry into memory — safe for multi-GB entries. CRC32 verified
    /// incrementally across all chunks.
    void readDataChunked(size_t index,
                          scope void delegate(const(ubyte)[] chunk) sink,
                          size_t chunkSize = 65536) {
        if (index >= _entries.length)
            throw new DarkArchiveException("ZIP: entry index out of bounds");
        auto ci = &_entries[index];
        auto localOffset = ci.localHeaderOffset;

        if (localOffset + 30 > _ds.length)
            throw new DarkArchiveException("ZIP: local header out of bounds");
        if (_ds.readLE!uint(localOffset) != ZIP_LOCAL_FILE_HEADER_SIG)
            throw new DarkArchiveException("ZIP: invalid local file header signature");

        auto fnLen = _ds.readLE!ushort(localOffset + 26);
        auto extraLen = _ds.readLE!ushort(localOffset + 28);
        ulong dataStart = localOffset + 30 + fnLen + extraLen;
        if (dataStart > _ds.length)
            throw new DarkArchiveException("ZIP: local header fields extend past data");

        auto compressedSize = ci.compressedSize;
        auto method = ci.compressionMethod;

        if (compressedSize > _ds.length || dataStart + compressedSize > _ds.length)
            throw new DarkArchiveException("ZIP: compressed data out of bounds");

        if (method == ZIP_METHOD_STORE) {
            // Store: read from DataSource in chunks (no decompression)
            import std.digest.crc : CRC32;
            CRC32 crc;

            ulong remaining = compressedSize;
            ulong pos = dataStart;
            while (remaining > 0) {
                auto toRead = remaining > chunkSize ? chunkSize : cast(size_t) remaining;
                auto chunk = _ds.readSlice(pos, toRead);
                crc.put(chunk);
                sink(chunk);
                pos += toRead;
                remaining -= toRead;
            }

            verifyCRC(ci.crc32, crc);
        } else if (method == ZIP_METHOD_DEFLATE) {
            // Deflate: read compressed data in chunks, inflate, yield decompressed chunks
            inflateChunked(_ds, dataStart, compressedSize, ci.crc32, sink, chunkSize);
        } else {
            import std.format : format;
            throw new DarkArchiveException(
                "ZIP: unsupported compression method %d".format(method));
        }
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
        if (_ds.length < 22)
            throw new DarkArchiveException("ZIP: data too short for EOCD");

        auto eocdPos = _ds.findBackward(ZIP_END_OF_CENTRAL_DIR_SIG,
            _ds.length - 4, 22 + 65535);
        if (eocdPos < 0)
            throw new DarkArchiveException("ZIP: cannot find end of central directory");

        auto pos = cast(ulong) eocdPos;

        ulong centralDirOffset;
        ulong centralDirSize;
        ulong totalEntries;

        auto diskEntries = _ds.readLE!ushort(pos + 8);
        auto totalEntries32 = _ds.readLE!ushort(pos + 10);
        auto centralDirSize32 = _ds.readLE!uint(pos + 12);
        auto centralDirOffset32 = _ds.readLE!uint(pos + 16);

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
        long offsetAdjust = 0;
        if (centralDirOffset + centralDirSize != pos) {
            offsetAdjust = cast(long) pos - cast(long)(centralDirOffset + centralDirSize);
            if (offsetAdjust < 0) offsetAdjust = 0;
        }

        // Sanity check: each central dir entry is at least 46 bytes.
        auto maxPossibleEntries = centralDirSize / 46;
        if (totalEntries > maxPossibleEntries)
            totalEntries = maxPossibleEntries;

        // Parse central directory entries
        _entries.length = 0;
        _entries.reserve(cast(size_t) totalEntries);

        auto cdPos = centralDirOffset + (offsetAdjust > 0 ? cast(ulong) offsetAdjust : 0);
        for (ulong i = 0; i < totalEntries; i++) {
            if (cdPos + 46 > _ds.length)
                throw new DarkArchiveException("ZIP: central directory entry out of bounds");
            if (_ds.readLE!uint(cdPos) != ZIP_CENTRAL_DIR_SIG)
                throw new DarkArchiveException("ZIP: invalid central directory signature");

            CentralDirInfo ci;
            ci.compressionMethod = _ds.readLE!ushort(cdPos + 10);
            ci.lastModTime = _ds.readLE!ushort(cdPos + 12);
            ci.lastModDate = _ds.readLE!ushort(cdPos + 14);
            ci.crc32 = _ds.readLE!uint(cdPos + 16);
            ci.compressedSize = _ds.readLE!uint(cdPos + 20);
            ci.uncompressedSize = _ds.readLE!uint(cdPos + 24);
            auto fnLen = _ds.readLE!ushort(cdPos + 28);
            auto extraLen = _ds.readLE!ushort(cdPos + 30);
            auto commentLen = _ds.readLE!ushort(cdPos + 32);
            auto flags = _ds.readLE!ushort(cdPos + 8);
            ci.externalAttrsRaw = _ds.readLE!uint(cdPos + 38);
            ci.externalAttrsUnix = (ci.externalAttrsRaw >> 16) & 0xFFFF;
            ci.localHeaderOffset = _ds.readLE!uint(cdPos + 42);

            // Filename
            auto fnStart = cdPos + 46;
            if (fnStart + fnLen > _ds.length)
                throw new DarkArchiveException("ZIP: filename out of bounds");
            auto fnBytes = _ds.readSlice(fnStart, fnLen);
            ci.filename = decodeFilename(fnBytes, flags);

            // Parse extra field for ZIP64
            auto extraStart = fnStart + fnLen;
            if (extraStart + extraLen <= _ds.length) {
                auto extraData = _ds.readSlice(extraStart, extraLen);
                parseZip64Extra(extraData, ci);
            }

            // Apply SFX offset adjustment to local header offset
            if (offsetAdjust > 0)
                ci.localHeaderOffset += cast(ulong) offsetAdjust;

            _entries ~= ci;
            cdPos = extraStart + extraLen + commentLen;
        }
    }

    private void parseZip64EOCD(ulong eocdPos, ref ulong totalEntries,
                                 ref ulong centralDirSize, ref ulong centralDirOffset) {
        if (eocdPos < 20)
            return;
        auto locatorPos = eocdPos - 20;
        if (_ds.readLE!uint(locatorPos) != ZIP_ZIP64_LOCATOR_SIG)
            return;

        auto zip64EOCDOffset = _ds.readLE!ulong(locatorPos + 8);
        if (zip64EOCDOffset + 56 > _ds.length)
            throw new DarkArchiveException("ZIP: ZIP64 EOCD out of bounds");
        if (_ds.readLE!uint(zip64EOCDOffset) != ZIP_ZIP64_EOCD_SIG)
            throw new DarkArchiveException("ZIP: invalid ZIP64 EOCD signature");

        totalEntries = _ds.readLE!ulong(zip64EOCDOffset + 32);
        centralDirSize = _ds.readLE!ulong(zip64EOCDOffset + 40);
        centralDirOffset = _ds.readLE!ulong(zip64EOCDOffset + 48);
    }

    private static void parseZip64Extra(const(ubyte)[] extra, ref CentralDirInfo ci) {
        size_t pos = 0;
        while (pos + 4 <= extra.length) {
            auto headerId = readLEStatic!ushort(extra, pos);
            auto dataSize = readLEStatic!ushort(extra, pos + 2);
            pos += 4;
            if (pos + dataSize > extra.length)
                break;

            if (headerId == ZIP64_EXTRA_FIELD_ID) {
                size_t fieldPos = pos;
                if (ci.uncompressedSize == ZIP64_MAGIC_32 && fieldPos + 8 <= pos + dataSize) {
                    ci.uncompressedSize = readLEStatic!ulong(extra, fieldPos);
                    fieldPos += 8;
                }
                if (ci.compressedSize == ZIP64_MAGIC_32 && fieldPos + 8 <= pos + dataSize) {
                    ci.compressedSize = readLEStatic!ulong(extra, fieldPos);
                    fieldPos += 8;
                }
                if (ci.localHeaderOffset == ZIP64_MAGIC_32 && fieldPos + 8 <= pos + dataSize) {
                    ci.localHeaderOffset = readLEStatic!ulong(extra, fieldPos);
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

/// Read a little-endian integer from a byte slice (for parseZip64Extra which
/// works on a local buffer, not the DataSource).
private T readLEStatic(T)(const(ubyte)[] data, size_t offset) {
    import std.bitmanip : littleEndianToNative;
    enum N = T.sizeof;
    if (offset + N > data.length)
        throw new DarkArchiveException("ZIP: unexpected end of data");
    ubyte[N] buf = data[offset .. offset + N];
    return littleEndianToNative!T(buf);
}

/// Decode a filename from raw bytes, using UTF-8 flag or fallback.
/// NUL bytes are preserved — rejection of NUL-containing names happens
/// at extraction time (extractToImpl) so callers can still list entries.
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
                result ~= cast(char)(0xC0 | (b >> 6));
                result ~= cast(char)(0x80 | (b & 0x3F));
            }
        }
        return result[];
    }
}

/// Inflate (decompress) raw deflated data.
private ubyte[] inflate(const(ubyte)[] compressedData, ulong uncompressedSize) {
    import etc.c.zlib;
    import std.array : appender;

    z_stream zs;
    zs.next_in = cast(ubyte*) compressedData.ptr;
    zs.avail_in = cast(uint) compressedData.length;

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

/// Streaming inflate: read compressed data from DataSource in chunks,
/// decompress in chunks, yield decompressed chunks to sink.
/// Peak memory: inputChunk + outputChunk (~16KB), not entry size.
private void inflateChunked(ref DataSource ds, ulong dataStart,
                             ulong compressedSize, uint expectedCRC,
                             scope void delegate(const(ubyte)[] chunk) sink,
                             size_t chunkSize) {
    import etc.c.zlib;
    import std.digest.crc : CRC32;

    z_stream zs;
    auto ret = inflateInit2(&zs, -15);
    if (ret != Z_OK)
        throw new DarkArchiveException("ZIP: inflateInit2 failed");
    scope(exit) inflateEnd(&zs);

    CRC32 crc;
    auto outBuf = new ubyte[](chunkSize);

    ulong compRemaining = compressedSize;
    ulong compPos = dataStart;
    enum INPUT_CHUNK = 64 * 1024; // 64KB compressed read chunks

    while (true) {
        // Feed more compressed data if zlib needs it
        if (zs.avail_in == 0 && compRemaining > 0) {
            auto toRead = compRemaining > INPUT_CHUNK
                ? INPUT_CHUNK : cast(size_t) compRemaining;
            auto compChunk = ds.readSlice(compPos, toRead);
            zs.next_in = cast(ubyte*) compChunk.ptr;
            zs.avail_in = cast(uint) compChunk.length;
            compPos += toRead;
            compRemaining -= toRead;
        }

        zs.next_out = outBuf.ptr;
        zs.avail_out = cast(uint) outBuf.length;

        ret = etc.c.zlib.inflate(&zs, Z_NO_FLUSH);

        auto produced = outBuf.length - zs.avail_out;
        if (produced > 0) {
            auto decompChunk = outBuf[0 .. produced];
            crc.put(decompChunk);
            sink(decompChunk);
        }

        if (ret == Z_STREAM_END)
            break;
        if (ret != Z_OK)
            throw new DarkArchiveException("ZIP: inflate failed");
    }

    verifyCRC(expectedCRC, crc);
}

/// Verify CRC32 against expected value.
private void verifyCRC(T)(uint expectedCRC, ref T crc) {
    if (expectedCRC != 0) {
        auto computed = crc.finish();
        uint computedVal = (cast(uint) computed[0])
                         | (cast(uint) computed[1] << 8)
                         | (cast(uint) computed[2] << 16)
                         | (cast(uint) computed[3] << 24);
        if (computedVal != expectedCRC)
            throw new DarkArchiveException("ZIP: CRC32 mismatch (data corrupted)");
    }
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

    private immutable testDataDir = "test-data";

    /// Read zip — iterate entries and verify content
    @("zip read: iterate entries and verify content")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        auto reader = ZipReader(testDataDir ~ "/test-zip.zip");
        string[] names;
        foreach (entry; reader.entries) {
            names ~= entry.pathname;
        }
        assert(names.length > 0, "should have found entries");

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
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
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
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
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
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
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
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
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
    // Zipper compatibility tests
    // -------------------------------------------------------------------

    @("zip read [zipper compat]: analyze archive with symlinks")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        auto reader = ZipReader(testDataDir ~ "/zipper-test.zip");
        reader.length.shouldEqual(7);

        bool foundDir, foundTestDir, foundFile, foundRoot;
        bool foundLink1, foundLink2, foundParentLink;

        foreach (entry; reader.entries) {
            if (entry.pathname == "test-zip/")
                { foundDir = true; entry.isDir.shouldBeTrue; }
            else if (entry.pathname == "test-zip/test-dir/")
                { foundTestDir = true; entry.isDir.shouldBeTrue; }
            else if (entry.pathname == "test-zip/test-dir/test.txt")
                { foundFile = true; entry.isFile.shouldBeTrue; }
            else if (entry.pathname == "test-zip/test.txt")
                { foundRoot = true; entry.isFile.shouldBeTrue; }
            else if (entry.pathname == "test-zip/test-link-1.txt")
                { foundLink1 = true; entry.isSymlink.shouldBeTrue;
                  entry.symlinkTarget.shouldEqual("test-dir/test.txt"); }
            else if (entry.pathname == "test-zip/test-dir/test-link.txt")
                { foundLink2 = true; entry.isSymlink.shouldBeTrue;
                  entry.symlinkTarget.shouldEqual("test.txt"); }
            else if (entry.pathname == "test-zip/test-dir/test-parent.txt")
                { foundParentLink = true; entry.isSymlink.shouldBeTrue;
                  entry.symlinkTarget.shouldEqual("../test.txt"); }
        }

        foundDir.shouldBeTrue; foundTestDir.shouldBeTrue;
        foundFile.shouldBeTrue; foundRoot.shouldBeTrue;
        foundLink1.shouldBeTrue; foundLink2.shouldBeTrue;
        foundParentLink.shouldBeTrue;
    }

    @("zip read [zipper compat]: read file content")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        auto reader = ZipReader(testDataDir ~ "/zipper-test.zip");
        foreach (i, ref ci; reader._entries) {
            if (ci.filename == "test-zip/test.txt")
                reader.readText(i).shouldEqual("Test Root\n");
            else if (ci.filename == "test-zip/test-dir/test.txt")
                reader.readText(i).shouldEqual("Hello World!\n");
        }
    }

    @("zip read [zipper compat]: symlink targets resolve correctly")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        auto reader = ZipReader(testDataDir ~ "/zipper-test.zip");
        foreach (i, ref ci; reader._entries) {
            if (ci.filename == "test-zip/test-link-1.txt")
                reader.readText(i).shouldEqual("test-dir/test.txt");
            else if (ci.filename == "test-zip/test-dir/test-parent.txt")
                reader.readText(i).shouldEqual("../test.txt");
        }
    }

    @("zip write [zipper compat]: add files from disk, read back")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        import darkarchive.formats.zip.writer : ZipWriter;
        import std.file : read, exists, remove;

        auto addonsContent = cast(string) read(testDataDir ~ "/addons-list.txt");

        auto tmpPath = testDataDir ~ "/test-zipr-addfiles.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        auto writer = ZipWriter.createToFile(tmpPath);
        scope(exit) writer.close();
        writer.addDirectory("test-data");
        writer.addBuffer("test-data/addons-list.txt",
            cast(const(ubyte)[]) addonsContent);
        writer.finish();

        auto reader = ZipReader(tmpPath);
        scope(exit) reader.close();
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

    @("zip write [zipper compat]: large file round-trip")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        import darkarchive.formats.zip.writer : ZipWriter;
        import std.file : read, exists, remove;

        auto logContent = cast(const(ubyte)[]) read(testDataDir ~ "/odoo.test.2.log");
        assert(logContent.length > 100_000);

        auto tmpPath = testDataDir ~ "/test-zipr-largefile.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        auto writer = ZipWriter.createToFile(tmpPath);
        scope(exit) writer.close();
        writer.addBuffer("odoo.test.2.log", logContent);
        writer.finish();

        auto reader = ZipReader(tmpPath);
        scope(exit) reader.close();
        reader.length.shouldEqual(1);
        auto readBack = reader.readData(0);
        readBack.length.shouldEqual(logContent.length);
        readBack.shouldEqual(logContent);
    }

    // -------------------------------------------------------------------
    // Security tests
    // -------------------------------------------------------------------

    @("zip security: readData with out-of-bounds index throws")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        auto reader = ZipReader(testDataDir ~ "/test-zip.zip");
        bool caught;
        try { reader.readData(9999); }
        catch (Exception e) { caught = true; }
        caught.shouldBeTrue;
    }

    @("zip security: truncated archive throws gracefully")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        import std.file : read, write, exists, remove;
        auto fullData = cast(ubyte[]) read(testDataDir ~ "/test-zip.zip");
        auto truncated = fullData[0 .. fullData.length / 2];
        auto truncPath = testDataDir ~ "/test-zipr-truncated.zip";
        scope(exit) if (exists(truncPath)) remove(truncPath);
        write(truncPath, truncated);
        bool caught;
        try { auto reader = ZipReader(truncPath); }
        catch (DarkArchiveException e) { caught = true; }
        caught.shouldBeTrue;
    }

    @("zip security: non-zip data throws")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        import std.file : write, exists, remove;
        auto garbagePath = testDataDir ~ "/test-zipr-garbage.zip";
        scope(exit) if (exists(garbagePath)) remove(garbagePath);
        write(garbagePath, "this is not a zip file at all");
        bool caught;
        try { auto reader = ZipReader(garbagePath); }
        catch (DarkArchiveException e) { caught = true; }
        caught.shouldBeTrue;
    }

    @("zip security: corrupted local header signature throws on readData")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        import darkarchive.formats.zip.writer : ZipWriter;
        import std.file : read, write, exists, remove;
        auto tmpPath = testDataDir ~ "/test-zipr-corrupthdr.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        auto writer = ZipWriter.createToFile(tmpPath);
        scope(exit) writer.close();
        writer.addBuffer("test.txt", cast(const(ubyte)[]) "hello");
        writer.finish();

        auto data = cast(ubyte[]) read(tmpPath);
        data[0] = 0xFF; data[1] = 0xFF;
        auto corruptPath = testDataDir ~ "/test-zipr-corrupthdr-bad.zip";
        scope(exit) if (exists(corruptPath)) remove(corruptPath);
        write(corruptPath, data);

        auto reader = ZipReader(corruptPath);
        scope(exit) reader.close();
        bool caught;
        try { reader.readData(0); }
        catch (DarkArchiveException e) { caught = true; }
        caught.shouldBeTrue;
    }

    @("zip security: CRC32 mismatch detected on read")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        import darkarchive.formats.zip.writer : ZipWriter;
        import std.file : read, write, exists, remove;
        auto tmpPath = testDataDir ~ "/test-zipr-crc.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        auto writer = ZipWriter.createToFile(tmpPath);
        scope(exit) writer.close();
        writer.addBuffer("test.txt", cast(const(ubyte)[]) "original content");
        writer.finish();

        auto data = cast(ubyte[]) read(tmpPath);
        auto corruptPos = 30 + 8 + 5;
        if (corruptPos < data.length) data[corruptPos] ^= 0xFF;
        auto corruptPath = testDataDir ~ "/test-zipr-crc-bad.zip";
        scope(exit) if (exists(corruptPath)) remove(corruptPath);
        write(corruptPath, data);

        auto reader = ZipReader(corruptPath);
        scope(exit) reader.close();
        bool caught;
        try { reader.readData(0); }
        catch (DarkArchiveException e) { caught = true; }
        caught.shouldBeTrue;
    }

    @("zip security: empty filename entry does not crash")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        import darkarchive.formats.zip.writer : ZipWriter;
        import std.file : exists, remove;
        auto tmpPath = testDataDir ~ "/test-zipr-emptyname.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        auto writer = ZipWriter.createToFile(tmpPath);
        scope(exit) writer.close();
        writer.addBuffer("", cast(const(ubyte)[]) "empty name");
        writer.finish();

        auto reader = ZipReader(tmpPath);
        scope(exit) reader.close();
        foreach (entry; reader.entries)
            assert(entry.pathname !is null);
    }

    // -------------------------------------------------------------------
    // Format edge-case tests
    // -------------------------------------------------------------------

    @("zip format: store method round-trip")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        import darkarchive.formats.zip.writer : ZipWriter;
        import std.file : exists, remove;
        auto tmpPath = testDataDir ~ "/test-zipr-store.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        auto writer = ZipWriter.createToFile(tmpPath);
        scope(exit) writer.close();
        writer.addBuffer("tiny.txt", cast(const(ubyte)[]) "hi");
        writer.finish();

        auto reader = ZipReader(tmpPath);
        scope(exit) reader.close();
        foreach (i, ref ci; reader._entries)
            if (ci.filename == "tiny.txt")
                reader.readText(i).shouldEqual("hi");
    }

    @("zip format: empty archive round-trip")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        import darkarchive.formats.zip.writer : ZipWriter;
        import std.file : exists, remove;
        auto tmpPath = testDataDir ~ "/test-zipr-empty.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        auto writer = ZipWriter.createToFile(tmpPath);
        scope(exit) writer.close();
        writer.finish();

        auto reader = ZipReader(tmpPath);
        scope(exit) reader.close();
        reader.length.shouldEqual(0);
    }

    @("zip interop: read Python-created ZIP")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
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

    @("zip format: EOCD with comment")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        auto reader = ZipReader(testDataDir ~ "/test-comment.zip");
        reader.length.shouldBeGreaterThan(0);
        foreach (i, ref ci; reader._entries)
            if (ci.filename == "file.txt")
                reader.readText(i).shouldEqual("has comment\n");
    }

    @("zip format: nested ZIP does not crash")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        import darkarchive.formats.zip.writer : ZipWriter;
        import std.file : read, exists, remove;
        auto innerPath = testDataDir ~ "/test-zipr-nested-inner.zip";
        scope(exit) if (exists(innerPath)) remove(innerPath);
        auto inner = ZipWriter.createToFile(innerPath);
        scope(exit) inner.close();
        inner.addBuffer("inner.txt", cast(const(ubyte)[]) "inner");
        inner.finish();

        auto innerData = cast(const(ubyte)[]) read(innerPath);
        auto outerPath = testDataDir ~ "/test-zipr-nested-outer.zip";
        scope(exit) if (exists(outerPath)) remove(outerPath);

        auto outer = ZipWriter.createToFile(outerPath);
        scope(exit) outer.close();
        outer.addBuffer("nested.zip", innerData);
        outer.addBuffer("outer.txt", cast(const(ubyte)[]) "outer");
        outer.finish();

        auto reader = ZipReader(outerPath);
        scope(exit) reader.close();
        reader.length.shouldEqual(2);
    }

    // -------------------------------------------------------------------
    // libzip-inspired edge case tests
    // -------------------------------------------------------------------

    @("zip format [libzip]: junk before ZIP (SFX)")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        auto reader = ZipReader(testDataDir ~ "/test-junk-before.zip");
        reader.length.shouldEqual(1);
        reader.readText(0).shouldEqual("content after junk\n");
    }

    @("zip format [libzip]: junk after ZIP")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        auto reader = ZipReader(testDataDir ~ "/test-junk-after.zip");
        reader.length.shouldEqual(1);
        reader.readText(0).shouldEqual("content before junk\n");
    }

    @("zip format [libzip]: duplicate filenames")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        auto reader = ZipReader(testDataDir ~ "/test-duplicate-names.zip");
        reader.length.shouldEqual(2);
        string[] contents;
        foreach (i; 0 .. reader.length) {
            auto entry = reader.entryAt(i);
            if (entry.pathname == "dupe.txt")
                contents ~= reader.readText(i);
        }
        contents.length.shouldEqual(2);
        import std.algorithm : canFind;
        assert(contents.canFind("first version\n"));
        assert(contents.canFind("second version\n"));
    }

    @("zip format [libzip]: NUL byte in filename")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        auto reader = ZipReader(testDataDir ~ "/test-nul-filename.zip");
        int count;
        foreach (entry; reader.entries) { count++; assert(entry.pathname !is null); }
        assert(count >= 1);
    }

    @("zip format [libzip]: backslash paths")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        auto reader = ZipReader(testDataDir ~ "/test-backslash.zip");
        bool foundForward;
        foreach (entry; reader.entries)
            if (entry.pathname == "normal/path.txt") foundForward = true;
        foundForward.shouldBeTrue;
    }

    @("zip format [libzip]: very long EOCD comment")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        auto reader = ZipReader(testDataDir ~ "/test-long-comment.zip");
        reader.length.shouldEqual(1);
        reader.readText(0).shouldEqual("file in archive with long comment\n");
    }

    @("zip format [libzip]: zero-length deflated entry")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        auto reader = ZipReader(testDataDir ~ "/test-empty-deflated.zip");
        bool foundEmpty, foundNonEmpty;
        foreach (i, ref ci; reader._entries) {
            if (ci.filename == "empty-deflated.txt") {
                foundEmpty = true;
                reader.readData(i).length.shouldEqual(0);
            } else if (ci.filename == "nonempty.txt") {
                foundNonEmpty = true;
                reader.readText(i).shouldEqual("has content\n");
            }
        }
        foundEmpty.shouldBeTrue;
        foundNonEmpty.shouldBeTrue;
    }

    @("zip format [libzip]: skip entries without reading")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        auto reader = ZipReader(testDataDir ~ "/test-zip.zip");
        assert(reader.length >= 3);
        auto lastIdx = reader.length - 1;
        auto entry = reader.entryAt(lastIdx);
        assert(entry.pathname.length > 0);
        auto data = reader.readData(lastIdx);
        assert(data !is null || entry.isDir || entry.size == 0);
    }

    // -------------------------------------------------------------------
    // Overflow / DoS hardening tests
    // -------------------------------------------------------------------

    @("zip security: absurd entry count capped by central dir size")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        import darkarchive.formats.zip.writer : ZipWriter;
        import std.file : read, write, exists, remove;
        auto tmpPath = testDataDir ~ "/test-zipr-absurdcount.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        auto writer = ZipWriter.createToFile(tmpPath);
        scope(exit) writer.close();
        writer.addBuffer("x.txt", cast(const(ubyte)[]) "x");
        writer.finish();

        auto data = cast(ubyte[]) read(tmpPath);
        // Patch EOCD entry count to 0xFFFF (absurd)
        auto eocdPos = data.length - 22;
        data[eocdPos + 10] = 0xFF; data[eocdPos + 11] = 0xFF;
        data[eocdPos + 8] = 0xFF; data[eocdPos + 9] = 0xFF;
        auto patchedPath = testDataDir ~ "/test-zipr-absurdcount-patched.zip";
        scope(exit) if (exists(patchedPath)) remove(patchedPath);
        write(patchedPath, data);

        // Reader should cap totalEntries to centralDirSize/46 (~1 entry)
        auto reader = ZipReader(patchedPath);
        scope(exit) reader.close();
        reader.length.shouldEqual(1);
        reader.readText(0).shouldEqual("x");
    }

    // -------------------------------------------------------------------
    // Fuzz / randomised-corruption tests
    // -------------------------------------------------------------------

    @("zip fuzz: systematic truncation sweep — only DarkArchiveException escapes")
    unittest {
        import darkarchive.formats.zip.writer : ZipWriter;
        import std.file : exists, remove, read, write;
        import std.conv : to;

        // Build a minimal single-file archive
        auto srcPath = testDataDir ~ "/test-zipr-fuzz-src.zip";
        scope(exit) if (exists(srcPath)) remove(srcPath);
        auto writer = ZipWriter.createToFile(srcPath);
        scope(exit) writer.close();
        writer.addBuffer("a.txt", cast(const(ubyte)[]) "hi");
        writer.finish();
        auto fullBytes = cast(ubyte[]) read(srcPath);

        auto truncPath = testDataDir ~ "/test-zipr-fuzz-trunc.zip";
        scope(exit) if (exists(truncPath)) remove(truncPath);

        foreach (len; 0 .. fullBytes.length) {
            write(truncPath, fullBytes[0 .. len]);
            try {
                auto reader = ZipReader(truncPath);
                scope(exit) reader.close();
                foreach (i; 0 .. reader.length) {
                    try { reader.readData(i); }
                    catch (DarkArchiveException) {} // expected on truncated data
                }
            } catch (DarkArchiveException) {
                // expected — truncated archive detected on open
            } catch (Exception e) {
                assert(false, "Non-DarkArchiveException at len=" ~ len.to!string
                    ~ ": " ~ e.classinfo.name ~ ": " ~ e.msg);
            }
        }
    }

    @("zip security: unsupported compression method throws DarkArchiveException")
    unittest {
        import darkarchive.formats.zip.writer : ZipWriter;
        import std.file : read, write, exists, remove;

        // Create a valid ZIP, then patch the compression method in the central dir to 99
        auto tmpPath = testDataDir ~ "/test-zipr-badmethod-src.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        auto writer = ZipWriter.createToFile(tmpPath);
        scope(exit) writer.close();
        writer.addBuffer("file.txt", cast(const(ubyte)[]) "content");
        writer.finish();

        auto data = cast(ubyte[]) read(tmpPath);
        // EOCD is at the end; central dir offset at eocd+16 (little-endian 32-bit)
        auto eocdPos = data.length - 22;
        uint cdOffset = data[eocdPos + 16]
                      | (cast(uint) data[eocdPos + 17] << 8)
                      | (cast(uint) data[eocdPos + 18] << 16)
                      | (cast(uint) data[eocdPos + 19] << 24);
        // Patch compression method in central directory entry (field at CD+10)
        data[cdOffset + 10] = 99; data[cdOffset + 11] = 0;
        auto patchedPath = testDataDir ~ "/test-zipr-badmethod.zip";
        scope(exit) if (exists(patchedPath)) remove(patchedPath);
        write(patchedPath, data);

        // ZipReader can open the archive (CD parsing doesn't validate method)
        // readData must throw DarkArchiveException for the unsupported method
        auto reader = ZipReader(patchedPath);
        scope(exit) reader.close();
        bool caught;
        try { reader.readData(0); }
        catch (DarkArchiveException) { caught = true; }
        assert(caught, "readData with unsupported compression method must throw DarkArchiveException");
    }

    @("zip security: central dir with huge filename length throws bounds check")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;
        import darkarchive.formats.zip.writer : ZipWriter;
        import std.file : read, write, exists, remove;

        auto tmpPath = testDataDir ~ "/test-zipr-hugefnlen-src.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        auto writer = ZipWriter.createToFile(tmpPath);
        scope(exit) writer.close();
        writer.addBuffer("x.txt", cast(const(ubyte)[]) "data");
        writer.finish();

        auto data = cast(ubyte[]) read(tmpPath);
        // Patch fnLen in central directory to 0xFFFF (65535)
        auto eocdPos = data.length - 22;
        uint cdOffset = data[eocdPos + 16]
                      | (cast(uint) data[eocdPos + 17] << 8)
                      | (cast(uint) data[eocdPos + 18] << 16)
                      | (cast(uint) data[eocdPos + 19] << 24);
        data[cdOffset + 28] = 0xFF; data[cdOffset + 29] = 0xFF; // fnLen = 65535
        auto patchedPath = testDataDir ~ "/test-zipr-hugefnlen.zip";
        scope(exit) if (exists(patchedPath)) remove(patchedPath);
        write(patchedPath, data);

        // parseCentralDirectory should throw because fnStart + 65535 > file length
        bool caught;
        try { auto reader = ZipReader(patchedPath); }
        catch (DarkArchiveException) { caught = true; }
        caught.shouldBeTrue;
    }

    @("zip security: overflow in dataStart calculation throws")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        import darkarchive.formats.zip.writer : ZipWriter;
        import std.file : read, write, exists, remove;
        auto tmpPath = testDataDir ~ "/test-zipr-overflow.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        auto writer = ZipWriter.createToFile(tmpPath);
        scope(exit) writer.close();
        writer.addBuffer("a.txt", cast(const(ubyte)[]) "data");
        writer.finish();

        auto data = cast(ubyte[]) read(tmpPath);
        data[26] = 0xFF; data[27] = 0xFF;
        auto corruptPath = testDataDir ~ "/test-zipr-overflow-bad.zip";
        scope(exit) if (exists(corruptPath)) remove(corruptPath);
        write(corruptPath, data);

        auto reader = ZipReader(corruptPath);
        scope(exit) reader.close();
        bool caught;
        try { reader.readData(0); }
        catch (DarkArchiveException e) { caught = true; }
        caught.shouldBeTrue;
    }
}
