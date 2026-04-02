/// TAR archive writer — pure D implementation.
///
/// Creates TAR archives in ustar format with pax extended headers
/// for UTF-8 pathnames and large sizes.
/// Supports file-backed and custom sink streaming modes.
module darkarchive.formats.tar.writer;

import std.conv : octal;
import std.bitmanip : nativeToLittleEndian;

import darkarchive.exception : DarkArchiveException;
import darkarchive.formats.tar.types;

/// Writes a TAR archive to a file or custom sink.
struct TarWriter {
    private {
        // Sink mode (file, gzip compressor, etc.)
        void delegate(const(ubyte)[]) _sink;
        void delegate() _sinkFinish;
        // Shared state
        bool _finished;
    }

    /// Create a file-backed writer (streaming, constant memory).
    static TarWriter createToFile(string path) {
        import std.stdio : File;
        auto f = new File(path, "wb");
        TarWriter w;
        w._sink = (const(ubyte)[] bytes) { f.rawWrite(bytes); };
        w._sinkFinish = () { f.close(); };
        w._finished = false;
        return w;
    }

    /// Create a writer that pipes through a custom sink (e.g., gzip compressor).
    static TarWriter createToSink(
            void delegate(const(ubyte)[]) sink,
            void delegate() sinkFinish = null) {
        TarWriter w;
        w._sink = sink;
        w._sinkFinish = sinkFinish;
        w._finished = false;
        return w;
    }

    /// Add a file from a memory buffer.
    ref TarWriter addBuffer(string archiveName, const(ubyte)[] fileData,
                             uint permissions = octal!644) return {
        auto paxHandlesSize = writePaxIfNeeded(archiveName, fileData.length);
        writeHeader(archiveName, '0',
            paxHandlesSize ? 0 : fileData.length, permissions, null);
        writeData(fileData);
        return this;
    }

    /// Add an empty directory.
    ref TarWriter addDirectory(string archiveName,
                                uint permissions = octal!755) return {
        if (archiveName.length == 0 || archiveName[$ - 1] != '/')
            archiveName ~= '/';
        writePaxIfNeeded(archiveName, 0);
        writeHeader(archiveName, '5', 0, permissions, null);
        return this;
    }

    /// Add a symlink.
    ref TarWriter addSymlink(string archiveName, string target,
                              uint permissions = octal!777) return {
        writePaxIfNeeded(archiveName, 0, target);
        writeHeader(archiveName, '2', 0, permissions, target);
        return this;
    }

    /// Add from a streaming source.
    ref TarWriter addStream(string archiveName,
                              scope void delegate(scope void delegate(const(ubyte)[])) reader,
                              long size = -1,
                              uint permissions = octal!644) return {
        import std.array : appender;
        auto buf = appender!(ubyte[])();
        reader((const(ubyte)[] chunk) { buf ~= chunk; });
        addBuffer(archiveName, buf[], permissions);
        return this;
    }

    /// Finalize the archive — write two zero blocks.
    void finish() {
        if (_finished) return;
        _finished = true;
        ubyte[TAR_BLOCK_SIZE * 2] zeros = 0;
        output(zeros[]);
        if (_sinkFinish !is null)
            _sinkFinish();
    }

    /// Close writer.
    void close() {
        if (!_finished) finish();
    }

    /// For testing writeOctal
    static void testWriteOctal(ubyte[] field, ulong value) {
        writeOctal(field, value);
    }

    // -- Private --

    /// Returns true if pax handled the size field.
    private bool writePaxIfNeeded(string name, ulong size, string linkname = null) {
        string[string] attrs;
        bool handlesSize;

        if (name.length > 100 || needsPaxEncoding(name))
            attrs["path"] = name;
        if (linkname !is null && (linkname.length > 100 || needsPaxEncoding(linkname)))
            attrs["linkpath"] = linkname;
        if (size > 0x1FFFFFFFF) {
            attrs["size"] = formatDecimal(size);
            handlesSize = true;
        }

        if (attrs.length == 0)
            return false;

        auto paxData = encodePaxData(attrs);
        writeHeader("PaxHeader", 'x', paxData.length, octal!644, null);
        writeData(cast(const(ubyte)[]) paxData);
        return handlesSize;
    }

    private void writeHeader(string name, char typeflag, ulong size,
                              uint permissions, string linkname) {
        ubyte[TAR_BLOCK_SIZE] header;
        header[] = 0;

        auto nameBytes = cast(const(ubyte)[]) name;
        auto nameLen = nameBytes.length > 100 ? 100 : nameBytes.length;
        header[0 .. nameLen] = nameBytes[0 .. nameLen];

        writeOctal(header[100 .. 108], permissions);
        writeOctal(header[108 .. 116], 0); // UID
        writeOctal(header[116 .. 124], 0); // GID
        writeOctal(header[124 .. 136], size);
        import core.stdc.time : time;
        writeOctal(header[136 .. 148], cast(ulong) time(null));
        header[156] = cast(ubyte) typeflag;

        if (linkname !is null) {
            auto lnBytes = cast(const(ubyte)[]) linkname;
            auto lnLen = lnBytes.length > 100 ? 100 : lnBytes.length;
            header[157 .. 157 + lnLen] = lnBytes[0 .. lnLen];
        }

        header[257 .. 263] = cast(const(ubyte)[]) "ustar\0";
        header[263 .. 265] = cast(const(ubyte)[]) "00";

        computeChecksum(header);
        output(header[]);
    }

    private void writeData(const(ubyte)[] fileData) {
        if (fileData.length == 0) return;
        output(fileData);
        auto remainder = fileData.length % TAR_BLOCK_SIZE;
        if (remainder > 0) {
            ubyte[TAR_BLOCK_SIZE] padding = 0;
            output(padding[0 .. TAR_BLOCK_SIZE - remainder]);
        }
    }

    /// Write bytes to output sink.
    private void output(const(ubyte)[] bytes) {
        if (_sink is null)
            throw new DarkArchiveException("TarWriter: no output target configured");
        _sink(bytes);
    }

    private static void computeChecksum(ref ubyte[TAR_BLOCK_SIZE] header) {
        header[148 .. 156] = ' ';
        uint sum = 0;
        foreach (b; header)
            sum += b;
        writeOctal(header[148 .. 156], sum);
        header[155] = ' ';
    }

    private static void writeOctal(ubyte[] field, ulong value) {
        import darkarchive.exception : DarkArchiveException;

        auto len = field.length;
        auto maxDigits = len - 1;
        ulong maxValue = 1;
        foreach (_; 0 .. maxDigits)
            maxValue *= 8;
        maxValue -= 1;

        if (value > maxValue)
            throw new DarkArchiveException("TAR: value too large for octal field");

        field[] = '0';
        field[len - 1] = 0;

        if (value == 0) return;

        for (size_t i = len - 2; i < len && value > 0; i--) {
            field[i] = cast(ubyte)('0' + (value & 7));
            value >>= 3;
        }
    }
}

private bool needsPaxEncoding(string s) {
    foreach (c; s)
        if (c > 0x7E || c < 0x20) return true;
    return false;
}

private string encodePaxData(string[string] attrs) {
    import std.array : appender;
    auto result = appender!string();

    foreach (key, value; attrs) {
        auto content = key ~ "=" ~ value ~ "\n";
        auto contentLen = content.length;
        size_t totalLen = contentLen + 2;
        while (true) {
            auto lenStr = formatDecimal(totalLen);
            auto actual = lenStr.length + 1 + contentLen;
            if (actual == totalLen) break;
            totalLen = actual;
            if (totalLen > contentLen + 20) break;
        }
        result ~= formatDecimal(totalLen);
        result ~= ' ';
        result ~= content;
    }

    return result[];
}

private string formatDecimal(ulong value) {
    import std.format : format;
    return "%d".format(value);
}

/// Compress data with gzip format.
ubyte[] gzipCompress(const(ubyte)[] data) {
    import std.zlib : Compress, HeaderFormat;
    auto c = new Compress(6, HeaderFormat.gzip);
    auto compressed = cast(ubyte[])(c.compress(data));
    auto tail = cast(ubyte[])(c.flush());
    return compressed ~ tail;
}



// ===========================================================================
// Unit tests
// ===========================================================================

version(unittest) {
    import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
    import darkarchive.formats.tar.reader : TarReader;

    @("tar write: round-trip with addBuffer")
    unittest {
        import std.file : exists, remove;
        auto tmpPath = "test-data/test-tarw-roundtrip.tar";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);

        auto writer = TarWriter.createToFile(tmpPath);
        writer
            .addBuffer("hello.txt", cast(const(ubyte)[]) "Hello World!")
            .addBuffer("sub/nested.txt", cast(const(ubyte)[]) "Nested content");
        writer.finish();

        auto reader = TarReader(tmpPath);
        bool foundHello, foundNested;
        foreach (entry; reader.entries) {
            if (entry.pathname == "hello.txt") {
                foundHello = true;
                reader.readText().shouldEqual("Hello World!");
            } else if (entry.pathname == "sub/nested.txt") {
                foundNested = true;
                reader.readText().shouldEqual("Nested content");
            }
        }
        foundHello.shouldBeTrue;
        foundNested.shouldBeTrue;
    }

    @("tar write: addDirectory")
    unittest {
        import std.file : exists, remove;
        auto tmpPath = "test-data/test-tarw-dir.tar";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);

        auto writer = TarWriter.createToFile(tmpPath);
        writer.addDirectory("mydir");
        writer.finish();

        auto reader = TarReader(tmpPath);
        foreach (entry; reader.entries)
            if (entry.pathname == "mydir/")
                entry.isDir.shouldBeTrue;
    }

    @("tar write: addSymlink")
    unittest {
        import std.file : exists, remove;
        auto tmpPath = "test-data/test-tarw-symlink.tar";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);

        auto writer = TarWriter.createToFile(tmpPath);
        writer.addSymlink("link.txt", "target.txt");
        writer.finish();

        auto reader = TarReader(tmpPath);
        foreach (entry; reader.entries) {
            if (entry.pathname == "link.txt") {
                entry.isSymlink.shouldBeTrue;
                entry.symlinkTarget.shouldEqual("target.txt");
            }
        }
    }

    @("tar write: long UTF-8 pathname via pax extended header")
    unittest {
        import std.array : replicate;
        import std.file : exists, remove;
        auto tmpPath = "test-data/test-tarw-pax-utf8.tar";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);

        auto longName = "深层目录/" ~ "子目录/".replicate(20) ~ "文件.txt";
        auto writer = TarWriter.createToFile(tmpPath);
        writer.addBuffer(longName, cast(const(ubyte)[]) "pax content");
        writer.finish();

        auto reader = TarReader(tmpPath);
        foreach (entry; reader.entries) {
            if (entry.pathname == longName) {
                reader.readText().shouldEqual("pax content");
                return;
            }
        }
        assert(false, "pax entry not found");
    }

    @("tar write: method chaining")
    unittest {
        import std.file : exists, remove;
        auto tmpPath = "test-data/test-tarw-chaining.tar";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);

        auto writer = TarWriter.createToFile(tmpPath);
        writer
            .addBuffer("a.txt", cast(const(ubyte)[]) "A")
            .addBuffer("b.txt", cast(const(ubyte)[]) "B")
            .addDirectory("dir");
        writer.finish();

        auto reader = TarReader(tmpPath);
        int count;
        foreach (entry; reader.entries) count++;
        count.shouldEqual(3);
    }

    @("tar.gz write: round-trip via gzipCompress + gunzip")
    unittest {
        import darkarchive.gzip : gunzip;
        import std.file : exists, remove, read, write;

        auto tarTmpPath = "test-data/test-tarw-gz-roundtrip.tar";
        auto gzTmpPath = "test-data/test-tarw-gz-roundtrip.tar.gz";
        scope(exit) {
            if (exists(tarTmpPath)) remove(tarTmpPath);
            if (exists(gzTmpPath)) remove(gzTmpPath);
        }

        auto writer = TarWriter.createToFile(tarTmpPath);
        writer
            .addBuffer("file-a.txt", cast(const(ubyte)[]) "Content A")
            .addBuffer("file-b.txt", cast(const(ubyte)[]) "Content B");
        writer.finish();

        auto tarData = cast(const(ubyte)[]) read(tarTmpPath);
        auto gzData = gzipCompress(tarData);
        assert(gzData.length > 0);
        write(gzTmpPath, gzData);

        // Decompress and read back
        auto decompressed = gunzip(cast(const(ubyte)[]) read(gzTmpPath));
        // Write decompressed tar to a file for TarReader
        auto tarTmpPath2 = "test-data/test-tarw-gz-roundtrip-dec.tar";
        scope(exit) if (exists(tarTmpPath2)) remove(tarTmpPath2);
        write(tarTmpPath2, decompressed);

        auto reader = TarReader(tarTmpPath2);
        int count;
        foreach (entry; reader.entries) {
            count++;
            if (entry.pathname == "file-a.txt")
                reader.readText().shouldEqual("Content A");
            else if (entry.pathname == "file-b.txt")
                reader.readText().shouldEqual("Content B");
        }
        count.shouldEqual(2);
    }

    @("tar write: single file, verify content")
    unittest {
        import std.file : exists, remove;
        auto tmpPath = "test-data/test-tarw-single.tar";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);

        auto writer = TarWriter.createToFile(tmpPath);
        writer.addBuffer("test.txt", cast(const(ubyte)[]) "tar file content");
        writer.finish();

        auto reader = TarReader(tmpPath);
        foreach (entry; reader.entries) {
            if (entry.pathname == "test.txt") {
                reader.readText().shouldEqual("tar file content");
                return;
            }
        }
        assert(false, "entry not found");
    }

    @("tar interop: written tar.gz readable by system tar")
    unittest {
        import std.file : write, remove, exists, read;
        import std.process : execute;

        auto tarTmpPath = "test-data/test-tarw-interop.tar";
        auto outPath = "test-data/test-tarw-interop.tar.gz";
        scope(exit) {
            if (exists(tarTmpPath)) remove(tarTmpPath);
            if (exists(outPath)) remove(outPath);
        }

        auto writer = TarWriter.createToFile(tarTmpPath);
        writer
            .addBuffer("hello.txt", cast(const(ubyte)[]) "Hello from D tar!\n")
            .addDirectory("mydir");
        writer.finish();

        auto tarData = cast(const(ubyte)[]) read(tarTmpPath);
        auto gzData = gzipCompress(tarData);
        write(outPath, gzData);

        auto result = execute(["tar", "tzf", outPath]);
        assert(result.status == 0, "tar failed: " ~ result.output);
        import std.algorithm : canFind;
        assert(result.output.canFind("hello.txt"), "tar listing missing hello.txt");
    }

    @("tar write security: octal overflow in size field throws")
    unittest {
        import darkarchive.exception : DarkArchiveException;
        ubyte[12] field;
        bool caught;
        try {
            TarWriter.testWriteOctal(field[], ulong.max);
        } catch (DarkArchiveException e) {
            caught = true;
        }
        caught.shouldBeTrue;
        TarWriter.testWriteOctal(field[], 420);
        assert(field[0] == '0' || (field[0] >= '1' && field[0] <= '7'));
    }

    /// File-backed writer round-trip
    @("tar write: file-backed streaming round-trip")
    unittest {
        import std.file : exists, remove;

        auto outPath = "test-data/test-file-writer.tar";
        scope(exit) if (exists(outPath)) remove(outPath);

        {
            auto writer = TarWriter.createToFile(outPath);
            writer
                .addBuffer("streamed.txt", cast(const(ubyte)[]) "streamed content")
                .addDirectory("streamdir");
            writer.finish();
        }

        {
            auto reader = TarReader(outPath);
            bool found;
            foreach (entry; reader.entries) {
                if (entry.pathname == "streamed.txt") {
                    found = true;
                    reader.readText().shouldEqual("streamed content");
                }
            }
            found.shouldBeTrue;
        }
    }
}
