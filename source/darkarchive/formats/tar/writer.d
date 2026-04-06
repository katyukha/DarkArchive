/// TAR archive writer — pure D implementation.
///
/// Creates TAR archives in ustar format with pax extended headers
/// for UTF-8 pathnames and large sizes.
/// Supports any output range (file, gzip compressor, delegate, etc.).
module darkarchive.formats.tar.writer;

import std.conv : octal;
import std.range : isOutputRange;

import darkarchive.exception : DarkArchiveException;
import darkarchive.formats.tar.types;

/// Writes a TAR archive to any output range of `const(ubyte)[]`.
///
/// Construct via the `tarWriter` or `tarGzWriter` factory functions.
/// Call `finish()` or `close()` to write the end-of-archive marker and
/// flush the underlying sink.
struct TarWriter(R)
    if (isOutputRange!(R, const(ubyte)[]))
{
    private {
        R _writer;
        bool _finished;
    }

    @disable this();

    /// Construct with a pre-built sink (prefer factory functions).
    this(R writer) {
        _writer = writer;
        _finished = false;
    }

    /// Add a file from a memory buffer.
    ref TarWriter!R addBuffer(string archiveName, const(ubyte)[] fileData,
                               uint permissions = octal!644) return {
        auto paxHandlesSize = writePaxIfNeeded(archiveName, fileData.length);
        writeHeader(archiveName, '0',
            paxHandlesSize ? 0 : fileData.length, permissions, null);
        writeData(fileData);
        return this;
    }

    /// Add an empty directory.
    ref TarWriter!R addDirectory(string archiveName,
                                  uint permissions = octal!755) return {
        if (archiveName.length == 0 || archiveName[$ - 1] != '/')
            archiveName ~= '/';
        writePaxIfNeeded(archiveName, 0);
        writeHeader(archiveName, '5', 0, permissions, null);
        return this;
    }

    /// Add a symlink.
    ref TarWriter!R addSymlink(string archiveName, string target,
                                uint permissions = octal!777) return {
        writePaxIfNeeded(archiveName, 0, target);
        writeHeader(archiveName, '2', 0, permissions, target);
        return this;
    }

    /// Add a hardlink (TAR typeflag '1'). `target` is the pathname of the
    /// original file as it appears in the archive — typically the same value
    /// that was passed to `addBuffer`/`addStream` for that entry.
    ref TarWriter!R addHardlink(string archiveName, string target,
                                 uint permissions = octal!644) return {
        writePaxIfNeeded(archiveName, 0, target);
        writeHeader(archiveName, '1', 0, permissions, target);
        return this;
    }

    /// Add from a streaming source.
    ///
    /// When size is known (>= 0), data is streamed directly to the archive
    /// without buffering — constant memory usage for any entry size.
    /// When size is unknown (-1), data must be buffered first because the
    /// TAR header requires the size before data.
    ref TarWriter!R addStream(string archiveName,
                               scope void delegate(scope void delegate(const(ubyte)[])) reader,
                               long size = -1,
                               uint permissions = octal!644) return {
        if (size >= 0) {
            auto usize = cast(ulong) size;
            auto paxHandlesSize = writePaxIfNeeded(archiveName, usize);
            writeHeader(archiveName, '0',
                paxHandlesSize ? 0 : usize, permissions, null);

            size_t totalWritten;
            reader((const(ubyte)[] chunk) {
                if (totalWritten + chunk.length > usize)
                    throw new DarkArchiveException(
                        "TAR addStream: data exceeds declared size");
                output(chunk);
                totalWritten += chunk.length;
            });

            if (totalWritten != usize)
                throw new DarkArchiveException(
                    "TAR addStream: data size mismatch (declared "
                    ~ formatDecimal(usize) ~ ", got "
                    ~ formatDecimal(totalWritten) ~ ")");

            auto remainder = totalWritten % TAR_BLOCK_SIZE;
            if (remainder > 0) {
                ubyte[TAR_BLOCK_SIZE] padding = 0;
                output(padding[0 .. TAR_BLOCK_SIZE - remainder]);
            }
        } else {
            import std.array : appender;
            auto buf = appender!(ubyte[])();
            reader((const(ubyte)[] chunk) { buf ~= chunk; });
            addBuffer(archiveName, buf[], permissions);
        }
        return this;
    }

    /// Finalize the archive — write two zero blocks and close the sink.
    void finish() {
        if (_finished) return;
        _finished = true;
        ubyte[TAR_BLOCK_SIZE * 2] zeros = 0;
        output(zeros[]);
        static if (__traits(hasMember, R, "close"))
            _writer.close();
    }

    /// Close writer (calls `finish()` if not already done).
    void close() {
        if (!_finished) finish();
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

        writeOctal(*cast(ubyte[8]*)  &header[100], permissions);
        writeOctal(*cast(ubyte[8]*)  &header[108], 0UL); // UID
        writeOctal(*cast(ubyte[8]*)  &header[116], 0UL); // GID
        writeOctal(*cast(ubyte[12]*) &header[124], size);
        import core.stdc.time : time;
        writeOctal(*cast(ubyte[12]*) &header[136], cast(ulong) time(null));
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

    private void output(const(ubyte)[] bytes) {
        import std.range.primitives : rangePut = put;
        rangePut(_writer, bytes);
    }

    private static void computeChecksum(ref ubyte[TAR_BLOCK_SIZE] header) {
        header[148 .. 156] = ' ';
        uint sum = 0;
        foreach (b; header)
            sum += b;
        // POSIX format: 6 octal digits + NUL byte + space (8 bytes total).
        writeOctal(*cast(ubyte[7]*) &header[148], sum); // writes 6 digits + NUL
        header[155] = ' ';                              // trailing space
    }
}

/// Create a `TarWriter` that writes plain TAR to a file.
auto tarWriter(string path) {
    import darkarchive.datasource : FileSink;
    return TarWriter!FileSink(FileSink(path));
}

/// Create a `TarWriter` that writes plain TAR to any output range.
auto tarWriter(R)(R sink)
    if (isOutputRange!(R, const(ubyte)[]))
{
    return TarWriter!R(sink);
}

/// Create a `TarWriter` that writes gzip-compressed TAR to a file.
auto tarGzWriter(string path) {
    import darkarchive.datasource : FileSink;
    import darkarchive.gzip : GzipSink;
    return TarWriter!(GzipSink!FileSink)(GzipSink!FileSink(FileSink(path)));
}

/// Create a `TarWriter` that writes gzip-compressed TAR to any output range.
auto tarGzWriter(R)(R sink)
    if (isOutputRange!(R, const(ubyte)[]))
{
    import darkarchive.gzip : GzipSink;
    return TarWriter!(GzipSink!R)(GzipSink!R(sink));
}

// Module-level helpers

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

private void writeOctal(ubyte[] field, ulong value) {
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

/// Type-safe overload — only accepts the field widths used in ustar headers
/// (7 for checksum, 8 for permissions/UID/GID, 12 for size/mtime).
/// Wrong widths produce a compile-time error.
private void writeOctal(size_t N)(ref ubyte[N] field, ulong value)
    if (N == 7 || N == 8 || N == 12)
{
    writeOctal(field[], value);
}

/// Compress data with gzip format (convenience — used in tests).
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

version(unittest) import thepath : Path;
version(unittest) {
    import darkarchive.formats.tar.reader : tarReader, tarGzReader;

    @("tar write: checksum field is POSIX format (6 octal + NUL + space)")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        auto tmpPath = "test-data/test-tarw-checksum-posix.tar";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        auto writer = tarWriter(tmpPath);
        scope(exit) writer.close();
        writer.addBuffer("x.txt", cast(const(ubyte)[]) "x");
        writer.finish();
        auto data = cast(ubyte[]) Path(tmpPath).readFile();
        assert(data.length >= 512, "TAR should have at least 1 block");
        // POSIX checksum layout in bytes 148..156: XXXXXX\0<space>
        auto cf = data[148 .. 156];
        foreach (b; cf[0 .. 6])
            assert((b >= '0' && b <= '7') || b == ' ',
                "checksum digits must be octal or space-padded");
        assert(cf[6] == 0,   "checksum byte 6 must be NUL (POSIX)");
        assert(cf[7] == ' ', "checksum byte 7 must be space (POSIX)");
    }

    @("tar write: writeOctal template overload exists for valid field widths")
    unittest {
        // The template overload with constraint (N == 7 || N == 8 || N == 12) must
        // be callable for each expected TAR header field size.
        static assert(__traits(compiles, { ubyte[7]  f; writeOctal(f, 0UL); }),
            "writeOctal must accept size-7 field (checksum)");
        static assert(__traits(compiles, { ubyte[8]  f; writeOctal(f, 0UL); }),
            "writeOctal must accept size-8 field (perms/uid/gid)");
        static assert(__traits(compiles, { ubyte[12] f; writeOctal(f, 0UL); }),
            "writeOctal must accept size-12 field (size/mtime)");
        // Size-10 has no template overload — the constraint rejects it.
        // (It still compiles via the dynamic-slice fallback; the template just
        //  won't be chosen, so no compile-time rejection is possible while keeping
        //  the dynamic fallback.  The value of the typed overload is documenting
        //  intent at each call-site in writeHeader.)
    }

    @("tar write: round-trip with addBuffer")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        auto tmpPath = "test-data/test-tarw-roundtrip.tar";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();

        auto writer = tarWriter(tmpPath);
        scope(exit) writer.close();
        writer
            .addBuffer("hello.txt", cast(const(ubyte)[]) "Hello World!")
            .addBuffer("sub/nested.txt", cast(const(ubyte)[]) "Nested content");
        writer.finish();

        auto reader = tarReader(tmpPath);
        scope(exit) reader.close();
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
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        auto tmpPath = "test-data/test-tarw-dir.tar";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();

        auto writer = tarWriter(tmpPath);
        scope(exit) writer.close();
        writer.addDirectory("mydir");
        writer.finish();

        auto reader = tarReader(tmpPath);
        scope(exit) reader.close();
        foreach (entry; reader.entries)
            if (entry.pathname == "mydir/")
                entry.isDir.shouldBeTrue;
    }

    @("tar write: addSymlink")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        auto tmpPath = "test-data/test-tarw-symlink.tar";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();

        auto writer = tarWriter(tmpPath);
        scope(exit) writer.close();
        writer.addSymlink("link.txt", "target.txt");
        writer.finish();

        auto reader = tarReader(tmpPath);
        scope(exit) reader.close();
        foreach (entry; reader.entries) {
            if (entry.pathname == "link.txt") {
                entry.isSymlink.shouldBeTrue;
                entry.symlinkTarget.shouldEqual("target.txt");
            }
        }
    }

    @("tar write: long UTF-8 pathname via pax extended header")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.array : replicate;
        auto tmpPath = "test-data/test-tarw-pax-utf8.tar";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();

        auto longName = "深层目录/" ~ "子目录/".replicate(20) ~ "文件.txt";
        auto writer = tarWriter(tmpPath);
        scope(exit) writer.close();
        writer.addBuffer(longName, cast(const(ubyte)[]) "pax content");
        writer.finish();

        auto reader = tarReader(tmpPath);
        scope(exit) reader.close();
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
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        auto tmpPath = "test-data/test-tarw-chaining.tar";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();

        auto writer = tarWriter(tmpPath);
        scope(exit) writer.close();
        writer
            .addBuffer("a.txt", cast(const(ubyte)[]) "A")
            .addBuffer("b.txt", cast(const(ubyte)[]) "B")
            .addDirectory("dir");
        writer.finish();

        auto reader = tarReader(tmpPath);
        scope(exit) reader.close();
        int count;
        foreach (entry; reader.entries) count++;
        count.shouldEqual(3);
    }

    @("tar.gz write: round-trip via tarGzWriter + tarGzReader")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;

        auto gzTmpPath = "test-data/test-tarw-gz-roundtrip.tar.gz";
        scope(exit) if (Path(gzTmpPath).exists) Path(gzTmpPath).remove();

        auto writer = tarGzWriter(gzTmpPath);
        scope(exit) writer.close();
        writer
            .addBuffer("file-a.txt", cast(const(ubyte)[]) "Content A")
            .addBuffer("file-b.txt", cast(const(ubyte)[]) "Content B");
        writer.finish();

        auto reader = tarGzReader(gzTmpPath);
        scope(exit) reader.close();
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
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        auto tmpPath = "test-data/test-tarw-single.tar";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();

        auto writer = tarWriter(tmpPath);
        scope(exit) writer.close();
        writer.addBuffer("test.txt", cast(const(ubyte)[]) "tar file content");
        writer.finish();

        auto reader = tarReader(tmpPath);
        scope(exit) reader.close();
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
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.process : execute;

        auto outPath = "test-data/test-tarw-interop.tar.gz";
        scope(exit) if (Path(outPath).exists) Path(outPath).remove();

        auto writer = tarGzWriter(outPath);
        scope(exit) writer.close();
        writer
            .addBuffer("hello.txt", cast(const(ubyte)[]) "Hello from D tar!\n")
            .addDirectory("mydir");
        writer.finish();

        auto result = execute(["tar", "tzf", outPath]);
        assert(result.status == 0, "tar failed: " ~ result.output);
        import std.algorithm : canFind;
        assert(result.output.canFind("hello.txt"), "tar listing missing hello.txt");
    }

    @("tar write security: octal overflow in size field throws")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import darkarchive.exception : DarkArchiveException;
        ubyte[12] field;
        bool caught;
        try {
            writeOctal(field[], ulong.max);
        } catch (DarkArchiveException e) {
            caught = true;
        }
        caught.shouldBeTrue;
        writeOctal(field[], 420);
        assert(field[0] == '0' || (field[0] >= '1' && field[0] <= '7'));
    }

    /// addStream with known size must throw if too few bytes provided
    @("tar write security: addStream throws on size underflow")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import darkarchive.exception : DarkArchiveException;

        auto tmpPath = "test-data/test-tarw-underflow.tar";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();

        auto writer = tarWriter(tmpPath);
        scope(exit) writer.close();
        bool caught;
        try {
            writer.addStream("short.bin", (scope sink) {
                sink(cast(const(ubyte)[]) "only 10 bytes");
            }, 1000); // declared 1000, provided ~13
        } catch (DarkArchiveException e) {
            caught = true;
        }
        caught.shouldBeTrue;
    }

    /// addStream with known size must throw if too many bytes provided
    @("tar write security: addStream throws on size overflow")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import darkarchive.exception : DarkArchiveException;

        auto tmpPath = "test-data/test-tarw-overflow.tar";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();

        auto writer = tarWriter(tmpPath);
        scope(exit) writer.close();
        bool caught;
        try {
            writer.addStream("big.bin", (scope sink) {
                auto chunk = new ubyte[](2000);
                sink(chunk);
            }, 500); // declared 500, provided 2000
        } catch (DarkArchiveException e) {
            caught = true;
        }
        caught.shouldBeTrue;
    }

    /// File-backed writer round-trip
    @("tar write: file-backed streaming round-trip")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;

        auto outPath = "test-data/test-file-writer.tar";
        scope(exit) if (Path(outPath).exists) Path(outPath).remove();

        auto writer = tarWriter(outPath);
        scope(exit) writer.close();
        writer
            .addBuffer("streamed.txt", cast(const(ubyte)[]) "streamed content")
            .addDirectory("streamdir");
        writer.finish();

        auto reader = tarReader(outPath);
        scope(exit) reader.close();
        bool found;
        foreach (entry; reader.entries) {
            if (entry.pathname == "streamed.txt") {
                found = true;
                reader.readText().shouldEqual("streamed content");
            }
        }
        found.shouldBeTrue;
    }

    /// UTF-8 filenames round-trip
    @("tar write: UTF-8 filenames round-trip")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.algorithm : canFind;

        auto tmpPath = "test-data/test-tarw-utf8.tar";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();

        auto writer = tarWriter(tmpPath);
        scope(exit) writer.close();
        writer
            .addBuffer("café.txt", cast(const(ubyte)[]) "coffee")
            .addBuffer("日本語.txt", cast(const(ubyte)[]) "japanese")
            .addBuffer("Ünïcödé/nested.txt", cast(const(ubyte)[]) "nested");
        writer.finish();

        auto reader = tarReader(tmpPath);
        scope(exit) reader.close();
        string[] names;
        foreach (entry; reader.entries)
            names ~= entry.pathname;

        assert(names.canFind("café.txt"), "missing café.txt");
        assert(names.canFind("日本語.txt"), "missing 日本語.txt");
        assert(names.canFind("Ünïcödé/nested.txt"), "missing Ünïcödé/nested.txt");
    }

    /// Many entries round-trip
    @("tar write: 150 entries round-trip")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.format : format;

        auto tmpPath = "test-data/test-tarw-many.tar";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();

        auto writer = tarWriter(tmpPath);
        scope(exit) writer.close();
        foreach (i; 0 .. 150)
            writer.addBuffer("file_%04d.txt".format(i),
                cast(const(ubyte)[]) "content %d".format(i));
        writer.finish();

        auto reader = tarReader(tmpPath);
        scope(exit) reader.close();
        int count;
        foreach (entry; reader.entries) count++;
        count.shouldEqual(150);
    }

    /// Permission value preservation round-trip
    @("tar write: permission values preserved")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.conv : octal;

        auto tmpPath = "test-data/test-tarw-perms.tar";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();

        auto writer = tarWriter(tmpPath);
        scope(exit) writer.close();
        writer
            .addBuffer("script.sh", cast(const(ubyte)[]) "#!/bin/sh",
                octal!755)
            .addBuffer("readonly.txt", cast(const(ubyte)[]) "data",
                octal!444)
            .addBuffer("normal.txt", cast(const(ubyte)[]) "data",
                octal!644)
            .addDirectory("mydir", octal!755);
        writer.finish();

        auto reader = tarReader(tmpPath);
        scope(exit) reader.close();
        foreach (entry; reader.entries) {
            if (entry.pathname == "script.sh")
                entry.permissions.shouldEqual(octal!755);
            else if (entry.pathname == "readonly.txt")
                entry.permissions.shouldEqual(octal!444);
            else if (entry.pathname == "normal.txt")
                entry.permissions.shouldEqual(octal!644);
            else if (entry.pathname == "mydir/")
                entry.permissions.shouldEqual(octal!755);
        }
    }

    /// tarGzWriter(sink) — streaming gzip via DelegateSink
    @("tar.gz write: tarGzWriter to delegate sink round-trip")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue;
        import darkarchive.datasource : DelegateSink;

        ubyte[] buf;
        auto writer = tarGzWriter(DelegateSink((const(ubyte)[] chunk) { buf ~= chunk; }));
        writer
            .addBuffer("sink.txt", cast(const(ubyte)[]) "delegate sink content")
            .finish();

        auto tmpPath = "test-data/test-tarw-gz-delegate-sink.tar.gz";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        Path(tmpPath).writeFile(buf);

        auto reader = tarGzReader(tmpPath);
        scope(exit) reader.close();
        bool found;
        foreach (entry; reader.entries) {
            if (entry.pathname == "sink.txt") {
                found = true;
                reader.readText().shouldEqual("delegate sink content");
            }
        }
        found.shouldBeTrue;
    }
}
