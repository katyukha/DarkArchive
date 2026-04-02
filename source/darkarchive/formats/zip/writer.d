/// ZIP archive writer — pure D implementation.
///
/// Creates ZIP archives with Deflate or Store compression.
/// Supports UTF-8 filenames, ZIP64, and data descriptors for streaming.
module darkarchive.formats.zip.writer;

import std.bitmanip : nativeToLittleEndian;
import std.conv : octal;

import darkarchive.exception : DarkArchiveException;
import darkarchive.formats.zip.types;

/// Writes a ZIP archive directly to a file.
struct ZipWriter {
    private {
        import std.stdio : File;
        File* _file;
        ulong _filePos;  // track position for central directory offsets
        // Shared state
        LocalEntryInfo[] _localEntries;
        bool _finished;
    }

    /// Create a file-backed writer (streaming, constant memory).
    static ZipWriter createToFile(string path) {
        ZipWriter w;
        w._file = new File(path, "wb");
        w._filePos = 0;
        w._localEntries = [];
        w._finished = false;
        return w;
    }

    /// Add a file from a memory buffer.
    ref ZipWriter addBuffer(string archiveName, const(ubyte)[] data,
                             uint permissions = octal!644) return {
        import std.digest.crc : crc32Of;

        auto crc = crc32Of(data);
        uint crcVal = (cast(uint) crc[0])
                    | (cast(uint) crc[1] << 8)
                    | (cast(uint) crc[2] << 16)
                    | (cast(uint) crc[3] << 24);

        // Compress with deflate
        auto compressed = deflateData(data);

        // Use store if deflate doesn't help
        ushort method;
        const(ubyte)[] writeData;
        if (compressed.length < data.length) {
            method = ZIP_METHOD_DEFLATE;
            writeData = compressed;
        } else {
            method = ZIP_METHOD_STORE;
            writeData = data;
        }

        writeLocalEntry(archiveName, method, crcVal,
            writeData.length, data.length, writeData, permissions, false);

        return this;
    }

    /// Add an empty directory.
    ref ZipWriter addDirectory(string archiveName,
                                uint permissions = octal!755) return {
        if (archiveName.length == 0 || archiveName[$ - 1] != '/')
            archiveName ~= '/';

        writeLocalEntry(archiveName, ZIP_METHOD_STORE, 0, 0, 0, null, permissions, true);
        return this;
    }

    /// Add symlink entry. The target path is stored as the file data,
    /// and Unix symlink mode (0o120777) is set in external attributes.
    ref ZipWriter addSymlink(string archiveName, string target,
                              uint permissions = octal!777) return {
        import std.digest.crc : crc32Of;

        auto targetBytes = cast(const(ubyte)[]) target;
        auto crc = crc32Of(targetBytes);
        uint crcVal = (cast(uint) crc[0])
                    | (cast(uint) crc[1] << 8)
                    | (cast(uint) crc[2] << 16)
                    | (cast(uint) crc[3] << 24);

        writeLocalEntry(archiveName, ZIP_METHOD_STORE, crcVal,
            targetBytes.length, targetBytes.length, targetBytes,
            permissions, false, true);
        return this;
    }

    /// Add from a streaming source. Uses data descriptors since size is unknown upfront.
    ref ZipWriter addStream(string archiveName,
                              scope void delegate(scope void delegate(const(ubyte)[])) reader,
                              long size = -1,
                              uint permissions = octal!644) return {
        import std.digest.crc : CRC32;
        import std.array : appender;

        // Collect all data (we need CRC32 and sizes for the data descriptor)
        auto uncompBuf = appender!(ubyte[])();
        reader((const(ubyte)[] chunk) {
            uncompBuf ~= chunk;
        });
        auto uncompData = uncompBuf[];

        // Now treat it like addBuffer
        addBuffer(archiveName, uncompData, permissions);
        return this;
    }

    /// Close writer (for file mode).
    void close() {
        if (!_finished) finish();
        if (_file !is null)
            _file.close();
    }

    /// Finalize the archive — write central directory and EOCD.
    void finish() {
        if (_finished) return;
        _finished = true;

        auto centralDirOffset = cast(ulong) outputPos();

        // Write central directory entries
        foreach (ref le; _localEntries) {
            writeCentralDirEntry(le);
        }

        auto centralDirSize = outputPos() - centralDirOffset;
        auto entryCount = _localEntries.length;

        bool needZip64 = centralDirOffset >= ZIP64_MAGIC_32 ||
                         centralDirSize >= ZIP64_MAGIC_32 ||
                         entryCount >= ZIP64_MAGIC_16;

        if (needZip64) {
            writeZip64EOCD(entryCount, centralDirSize, centralDirOffset);
        }

        writeEOCD(entryCount, centralDirSize, centralDirOffset, needZip64);

        // Close file to flush all data to disk
        if (_file !is null) {
            _file.close();
            _file = null;
        }
    }

    // -- Private implementation --

    private void writeLocalEntry(string name, ushort method, uint crc,
                                  ulong compSize, ulong uncompSize,
                                  const(ubyte)[] compData,
                                  uint permissions, bool isDir,
                                  bool isSymlink = false) {
        auto localOffset = outputPos();

        ushort flags = ZIP_FLAG_UTF8; // Always write UTF-8 filenames
        auto nameBytes = cast(const(ubyte)[]) name;

        if (nameBytes.length > ushort.max)
            throw new DarkArchiveException("ZIP: filename too long (max 65535 bytes)");

        // Determine if we need ZIP64 extra field
        bool needZip64 = compSize >= ZIP64_MAGIC_32 || uncompSize >= ZIP64_MAGIC_32;
        ushort versionNeeded = needZip64 ? ZIP_VERSION_NEEDED_ZIP64 : ZIP_VERSION_NEEDED_DEFAULT;

        // Build extra field
        ubyte[] extra;
        if (needZip64) {
            extra.length = 4 + 16; // header(4) + uncompSize(8) + compSize(8)
            extra[0 .. 2] = nativeToLittleEndian!ushort(ZIP64_EXTRA_FIELD_ID);
            extra[2 .. 4] = nativeToLittleEndian!ushort(16);
            extra[4 .. 12] = nativeToLittleEndian!ulong(uncompSize);
            extra[12 .. 20] = nativeToLittleEndian!ulong(compSize);
        }

        // Local file header
        appendLE!uint(ZIP_LOCAL_FILE_HEADER_SIG);
        appendLE!ushort(versionNeeded);
        appendLE!ushort(flags);
        appendLE!ushort(method);
        appendLE!ushort(0); // mod time (TODO)
        appendLE!ushort(0); // mod date (TODO)
        appendLE!uint(crc);
        appendLE!uint(needZip64 ? ZIP64_MAGIC_32 : cast(uint) compSize);
        appendLE!uint(needZip64 ? ZIP64_MAGIC_32 : cast(uint) uncompSize);
        appendLE!ushort(cast(ushort) nameBytes.length);
        appendLE!ushort(cast(ushort) extra.length);
        output(nameBytes);
        output(extra);

        // Data
        if (compData !is null && compData.length > 0)
            output(compData);

        // Record for central directory
        _localEntries ~= LocalEntryInfo(
            name, method, crc,
            compSize, uncompSize,
            localOffset, flags, versionNeeded,
            permissions, isDir, isSymlink, extra.dup
        );
    }

    private void writeCentralDirEntry(ref LocalEntryInfo le) {
        auto nameBytes = cast(const(ubyte)[]) le.name;

        // External attributes: Unix mode in upper 16 bits
        uint externalAttrs;
        if (le.isDir)
            externalAttrs = ((le.permissions | 0x4000) << 16) | 0x10; // S_IFDIR + MS-DOS dir
        else if (le.isSymlink)
            externalAttrs = ((le.permissions | 0xA000) << 16); // S_IFLNK (0o120000)
        else
            externalAttrs = ((le.permissions | 0x8000) << 16); // S_IFREG

        bool needZip64Offset = le.localOffset >= ZIP64_MAGIC_32;
        bool needZip64 = le.compSize >= ZIP64_MAGIC_32 ||
                         le.uncompSize >= ZIP64_MAGIC_32 ||
                         needZip64Offset;

        // Build extra field for central dir
        ubyte[] extra;
        if (needZip64) {
            size_t sz = 0;
            if (le.uncompSize >= ZIP64_MAGIC_32) sz += 8;
            if (le.compSize >= ZIP64_MAGIC_32) sz += 8;
            if (needZip64Offset) sz += 8;

            extra.length = 4 + sz;
            extra[0 .. 2] = nativeToLittleEndian!ushort(ZIP64_EXTRA_FIELD_ID);
            extra[2 .. 4] = nativeToLittleEndian!ushort(cast(ushort) sz);
            size_t pos = 4;
            if (le.uncompSize >= ZIP64_MAGIC_32) {
                extra[pos .. pos + 8] = nativeToLittleEndian!ulong(le.uncompSize);
                pos += 8;
            }
            if (le.compSize >= ZIP64_MAGIC_32) {
                extra[pos .. pos + 8] = nativeToLittleEndian!ulong(le.compSize);
                pos += 8;
            }
            if (needZip64Offset) {
                extra[pos .. pos + 8] = nativeToLittleEndian!ulong(le.localOffset);
                pos += 8;
            }
        }

        appendLE!uint(ZIP_CENTRAL_DIR_SIG);
        appendLE!ushort(ZIP_VERSION_MADE_BY);
        appendLE!ushort(le.versionNeeded);
        appendLE!ushort(le.flags);
        appendLE!ushort(le.method);
        appendLE!ushort(0); // mod time
        appendLE!ushort(0); // mod date
        appendLE!uint(le.crc);
        appendLE!uint(le.compSize >= ZIP64_MAGIC_32 ? ZIP64_MAGIC_32 : cast(uint) le.compSize);
        appendLE!uint(le.uncompSize >= ZIP64_MAGIC_32 ? ZIP64_MAGIC_32 : cast(uint) le.uncompSize);
        appendLE!ushort(cast(ushort) nameBytes.length);
        appendLE!ushort(cast(ushort) extra.length);
        appendLE!ushort(0); // comment length
        appendLE!ushort(0); // disk number start
        appendLE!ushort(0); // internal attributes
        appendLE!uint(externalAttrs);
        appendLE!uint(needZip64Offset ? ZIP64_MAGIC_32 : cast(uint) le.localOffset);
        output(nameBytes);
        output(extra);
    }

    private void writeZip64EOCD(ulong entryCount, ulong centralDirSize, ulong centralDirOffset) {
        auto zip64EOCDOffset = outputPos();

        // ZIP64 End of Central Directory Record
        appendLE!uint(ZIP_ZIP64_EOCD_SIG);
        appendLE!ulong(44); // size of remaining record
        appendLE!ushort(ZIP_VERSION_MADE_BY);
        appendLE!ushort(ZIP_VERSION_NEEDED_ZIP64);
        appendLE!uint(0); // disk number
        appendLE!uint(0); // disk with central dir
        appendLE!ulong(entryCount);
        appendLE!ulong(entryCount);
        appendLE!ulong(centralDirSize);
        appendLE!ulong(centralDirOffset);

        // ZIP64 EOCD Locator
        appendLE!uint(ZIP_ZIP64_LOCATOR_SIG);
        appendLE!uint(0); // disk with ZIP64 EOCD
        appendLE!ulong(zip64EOCDOffset);
        appendLE!uint(1); // total disks
    }

    private void writeEOCD(ulong entryCount, ulong centralDirSize,
                            ulong centralDirOffset, bool needZip64) {
        appendLE!uint(ZIP_END_OF_CENTRAL_DIR_SIG);
        appendLE!ushort(0); // disk number
        appendLE!ushort(0); // disk with central dir
        appendLE!ushort(needZip64 ? ZIP64_MAGIC_16 : cast(ushort) entryCount);
        appendLE!ushort(needZip64 ? ZIP64_MAGIC_16 : cast(ushort) entryCount);
        appendLE!uint(needZip64 ? ZIP64_MAGIC_32 : cast(uint) centralDirSize);
        appendLE!uint(needZip64 ? ZIP64_MAGIC_32 : cast(uint) centralDirOffset);
        appendLE!ushort(0); // comment length
    }

    private void appendLE(T)(T value) {
        auto bytes = nativeToLittleEndian!T(value);
        output(bytes[]);
    }

    /// Write bytes to output file.
    private void output(const(ubyte)[] bytes) {
        if (_file is null)
            throw new DarkArchiveException("ZIP: no output file — use createToFile()");
        _file.rawWrite(bytes);
        _filePos += bytes.length;
    }

    /// Current output position.
    private ulong outputPos() {
        if (_file is null)
            throw new DarkArchiveException("ZIP: no output file — use createToFile()");
        return _filePos;
    }
}

/// Compress data with raw deflate (no zlib/gzip header).
/// ZIP format requires raw deflate (windowBits=-15).
private ubyte[] deflateData(const(ubyte)[] data) {
    import etc.c.zlib;
    import std.array : appender;

    if (data.length == 0)
        return [];

    z_stream zs;
    zs.next_in = cast(ubyte*) data.ptr;
    zs.avail_in = cast(uint) data.length;

    // -15 = raw deflate output (no zlib/gzip header)
    auto ret = deflateInit2(&zs, 6, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);
    if (ret != Z_OK)
        throw new DarkArchiveException("ZIP: deflateInit2 failed");
    scope(exit) deflateEnd(&zs);

    auto result = appender!(ubyte[])();
    ubyte[8192] outBuf;

    while (true) {
        zs.next_out = outBuf.ptr;
        zs.avail_out = cast(uint) outBuf.length;

        ret = deflate(&zs, Z_FINISH);
        auto produced = outBuf.length - zs.avail_out;
        if (produced > 0)
            result ~= outBuf[0 .. produced];

        if (ret == Z_STREAM_END)
            break;
        if (ret != Z_OK)
            throw new DarkArchiveException("ZIP: deflate failed");
    }

    return result[];
}

// -- Internal structures --

private struct LocalEntryInfo {
    string name;
    ushort method;
    uint crc;
    ulong compSize;
    ulong uncompSize;
    ulong localOffset;
    ushort flags;
    ushort versionNeeded;
    uint permissions;
    bool isDir;
    bool isSymlink;
    ubyte[] extra;
}


// ===========================================================================
// Unit tests
// ===========================================================================

version(unittest) {
    import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
    import darkarchive.formats.zip.reader : ZipReader;

    /// Write zip round-trip with addBuffer + addDirectory
    @("zip write: round-trip with addBuffer + addDirectory")
    unittest {
        import std.file : exists, remove;
        auto tmpPath = "test-data/test-zip-wrt-roundtrip.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);

        auto writer = ZipWriter.createToFile(tmpPath);
        writer
            .addBuffer("hello.txt", cast(const(ubyte)[]) "Hello World!")
            .addBuffer("data/nested.txt", cast(const(ubyte)[]) "Nested content")
            .addDirectory("emptydir");
        writer.finish();

        auto reader = ZipReader(tmpPath);
        scope(exit) reader.close();

        bool foundHello, foundNested, foundDir;
        size_t i;
        foreach (entry; reader.entries) {
            if (entry.pathname == "hello.txt") {
                foundHello = true;
                reader.readText(i).shouldEqual("Hello World!");
            } else if (entry.pathname == "data/nested.txt") {
                foundNested = true;
                reader.readText(i).shouldEqual("Nested content");
            } else if (entry.pathname == "emptydir/") {
                foundDir = true;
                entry.isDir.shouldBeTrue;
            }
            i++;
        }
        foundHello.shouldBeTrue;
        foundNested.shouldBeTrue;
        foundDir.shouldBeTrue;
    }

    /// Streaming write with addStream
    @("zip write: addStream streaming round-trip")
    unittest {
        import std.file : exists, remove;
        auto tmpPath = "test-data/test-zip-wrt-stream.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);

        auto writer = ZipWriter.createToFile(tmpPath);
        writer.addStream("streamed.txt", (scope sink) {
            sink(cast(const(ubyte)[]) "Streamed content ");
            sink(cast(const(ubyte)[]) "chunk1");
            sink(cast(const(ubyte)[]) "chunk2");
        });
        writer.finish();

        auto reader = ZipReader(tmpPath);
        scope(exit) reader.close();
        size_t i;
        foreach (entry; reader.entries) {
            if (entry.pathname == "streamed.txt")
                reader.readText(i).shouldEqual("Streamed content chunk1chunk2");
            i++;
        }
    }

    /// Method chaining
    @("zip write: method chaining")
    unittest {
        import std.file : exists, remove;
        auto tmpPath = "test-data/test-zip-wrt-chaining.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);

        auto writer = ZipWriter.createToFile(tmpPath);
        writer
            .addBuffer("a.txt", cast(const(ubyte)[]) "A")
            .addBuffer("b.txt", cast(const(ubyte)[]) "B")
            .addBuffer("c.txt", cast(const(ubyte)[]) "C");
        writer.finish();

        auto reader = ZipReader(tmpPath);
        scope(exit) reader.close();
        reader.length.shouldEqual(3);
    }

    /// Large entry — 32KB data
    @("zip write: large entry multi-chunk")
    unittest {
        import std.file : exists, remove;
        auto tmpPath = "test-data/test-zip-wrt-large.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);

        auto largeData = new ubyte[](32768);
        foreach (i, ref b; largeData)
            b = cast(ubyte)(i % 256);

        auto writer = ZipWriter.createToFile(tmpPath);
        writer.addBuffer("large.bin", largeData);
        writer.finish();

        auto reader = ZipReader(tmpPath);
        scope(exit) reader.close();
        size_t i;
        foreach (entry; reader.entries) {
            if (entry.pathname == "large.bin") {
                auto content = reader.readData(i);
                content.length.shouldEqual(32768);
                content.shouldEqual(largeData);
            }
            i++;
        }
    }

    /// Entry properties
    @("zip write: entry properties (isFile, isDir, size)")
    unittest {
        import std.file : exists, remove;
        auto tmpPath = "test-data/test-zip-wrt-props.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);

        auto writer = ZipWriter.createToFile(tmpPath);
        writer
            .addBuffer("file.txt", cast(const(ubyte)[]) "content")
            .addDirectory("mydir");
        writer.finish();

        auto reader = ZipReader(tmpPath);
        scope(exit) reader.close();
        foreach (entry; reader.entries) {
            if (entry.pathname == "file.txt") {
                entry.isFile.shouldBeTrue;
                entry.isDir.shouldBeFalse;
                entry.size.shouldEqual(7);
            } else if (entry.pathname == "mydir/") {
                entry.isDir.shouldBeTrue;
                entry.isFile.shouldBeFalse;
            }
        }
    }

    /// UTF-8 filenames in written archive
    @("zip write: UTF-8 filenames round-trip")
    unittest {
        import std.algorithm : canFind;
        import std.file : exists, remove;
        auto tmpPath = "test-data/test-zip-wrt-utf8.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);

        auto writer = ZipWriter.createToFile(tmpPath);
        writer
            .addBuffer("café.txt", cast(const(ubyte)[]) "coffee")
            .addBuffer("日本語.txt", cast(const(ubyte)[]) "japanese");
        writer.finish();

        auto reader = ZipReader(tmpPath);
        scope(exit) reader.close();
        string[] names;
        foreach (entry; reader.entries)
            names ~= entry.pathname;

        assert(names.canFind("café.txt"));
        assert(names.canFind("日本語.txt"));
    }

    /// Written ZIP is readable by ZipReader from file
    @("zip write: write to file, read back")
    unittest {
        import std.file : exists, remove;

        auto tmpPath = "test-data/test-zip-wrt-file-readback.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);

        auto writer = ZipWriter.createToFile(tmpPath);
        writer.addBuffer("test.txt", cast(const(ubyte)[]) "file content");
        writer.finish();

        auto reader = ZipReader(tmpPath);
        scope(exit) reader.close();

        reader.length.shouldEqual(1);
        reader.readText(0).shouldEqual("file content");
    }

    // -------------------------------------------------------------------
    // Security / edge-case tests
    // -------------------------------------------------------------------

    /// Written ZIP is readable by Python's zipfile
    @("zip interop: written ZIP readable by Python")
    unittest {
        import std.file : exists, remove;
        import std.process : execute;

        auto outPath = "test-data/test-zip-wrt-python-interop.zip";
        scope(exit) if (exists(outPath)) remove(outPath);

        auto writer = ZipWriter.createToFile(outPath);
        writer
            .addBuffer("greeting.txt", cast(const(ubyte)[]) "Hello from D!\n")
            .addBuffer("data/info.txt", cast(const(ubyte)[]) "D archive\n")
            .addDirectory("emptydir");
        writer.finish();

        // Verify with Python
        auto result = execute(["python3", "-c", `
import zipfile, sys
try:
    with zipfile.ZipFile('` ~ outPath ~ `', 'r') as zf:
        names = zf.namelist()
        assert 'greeting.txt' in names, f"missing greeting.txt: {names}"
        assert zf.read('greeting.txt') == b'Hello from D!\n', "content mismatch"
        assert 'data/info.txt' in names, f"missing data/info.txt: {names}"
        assert zf.read('data/info.txt') == b'D archive\n', "content mismatch"
    print("OK")
except Exception as e:
    print(f"FAIL: {e}")
    sys.exit(1)
`]);
        import std.string : strip;
        result.output.strip.shouldEqual("OK");
    }

    /// Filename > 65535 bytes must throw, not silently truncate
    @("zip write security: filename > 65535 bytes throws")
    unittest {
        import darkarchive.exception : DarkArchiveException;
        import std.array : replicate;
        import std.file : exists, remove;

        auto tmpPath = "test-data/test-zip-wrt-longname.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);

        auto longName = "a".replicate(65536); // one byte over ushort.max

        auto writer = ZipWriter.createToFile(tmpPath);
        bool caught;
        try {
            writer.addBuffer(longName, cast(const(ubyte)[]) "x");
        } catch (DarkArchiveException e) {
            caught = true;
        }
        caught.shouldBeTrue;
    }

    /// ZIP symlink round-trip: write symlink, read back
    @("zip write: symlink round-trip")
    unittest {
        import std.file : exists, remove;
        auto tmpPath = "test-data/test-zip-wrt-symlink.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);

        auto writer = ZipWriter.createToFile(tmpPath);
        writer.addBuffer("target.txt", cast(const(ubyte)[]) "target content");
        writer.addSymlink("link.txt", "target.txt");
        writer.finish();

        auto reader = ZipReader(tmpPath);
        scope(exit) reader.close();
        reader.length.shouldEqual(2);

        bool foundTarget, foundLink;
        foreach (entry; reader.entries) {
            if (entry.pathname == "target.txt") {
                foundTarget = true;
                entry.isFile.shouldBeTrue;
            } else if (entry.pathname == "link.txt") {
                foundLink = true;
                entry.isSymlink.shouldBeTrue;
                entry.symlinkTarget.shouldEqual("target.txt");
            }
        }
        foundTarget.shouldBeTrue;
        foundLink.shouldBeTrue;
    }
}
