/// TAR archive writer — pure D implementation.
///
/// Creates TAR archives in ustar format with pax extended headers
/// for UTF-8 pathnames and large sizes.
module darkarchive.formats.tar.writer;

import std.conv : octal;
import std.bitmanip : nativeToLittleEndian;

import darkarchive.exception : DarkArchiveException;
import darkarchive.formats.tar.types;

/// Writes a TAR archive to a growing memory buffer.
struct TarWriter {
    private {
        ubyte[] _buf;
        bool _finished;
    }

    static TarWriter create() {
        TarWriter w;
        w._buf = [];
        w._finished = false;
        return w;
    }

    /// Add a file from a memory buffer.
    ref TarWriter addBuffer(string archiveName, const(ubyte)[] fileData,
                             uint permissions = octal!644) return {
        writePaxIfNeeded(archiveName, fileData.length);
        writeHeader(archiveName, '0', fileData.length, permissions, null);
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
        // Collect all data
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
        // Two 512-byte zero blocks mark end of archive
        _buf.length += TAR_BLOCK_SIZE * 2;
    }

    /// Get the written archive data. Calls finish() if not already done.
    const(ubyte)[] data() {
        if (!_finished) finish();
        return _buf;
    }

    // -- Private --

    private void writePaxIfNeeded(string name, ulong size, string linkname = null) {
        string[string] attrs;

        // Need pax extended header if name > 100 chars or contains non-ASCII
        if (name.length > 100 || needsPaxEncoding(name))
            attrs["path"] = name;
        if (linkname !is null && (linkname.length > 100 || needsPaxEncoding(linkname)))
            attrs["linkpath"] = linkname;
        if (size > 0x1FFFFFFFF) // > max octal in 12 bytes
            attrs["size"] = formatDecimal(size);

        if (attrs.length == 0)
            return;

        auto paxData = encodePaxData(attrs);
        writeHeader("PaxHeader", 'x', paxData.length, octal!644, null);
        writeData(cast(const(ubyte)[]) paxData);
    }

    private void writeHeader(string name, char typeflag, ulong size,
                              uint permissions, string linkname) {
        ubyte[TAR_BLOCK_SIZE] header;
        header[] = 0;

        // Name (truncate to 100 if needed — pax handles the full name)
        auto nameBytes = cast(const(ubyte)[]) name;
        auto nameLen = nameBytes.length > 100 ? 100 : nameBytes.length;
        header[0 .. nameLen] = nameBytes[0 .. nameLen];

        // Mode
        writeOctal(header[100 .. 108], permissions);
        // UID
        writeOctal(header[108 .. 116], 0);
        // GID
        writeOctal(header[116 .. 124], 0);
        // Size
        writeOctal(header[124 .. 136], size);
        // Mtime (current time)
        import core.stdc.time : time;
        writeOctal(header[136 .. 148], cast(ulong) time(null));
        // Typeflag
        header[156] = cast(ubyte) typeflag;

        // Linkname
        if (linkname !is null) {
            auto lnBytes = cast(const(ubyte)[]) linkname;
            auto lnLen = lnBytes.length > 100 ? 100 : lnBytes.length;
            header[157 .. 157 + lnLen] = lnBytes[0 .. lnLen];
        }

        // Magic + version (ustar)
        header[257 .. 263] = cast(const(ubyte)[]) "ustar\0";
        header[263 .. 265] = cast(const(ubyte)[]) "00";

        // Compute checksum
        computeChecksum(header);

        _buf ~= header[];
    }

    private void writeData(const(ubyte)[] fileData) {
        if (fileData.length == 0) return;
        _buf ~= fileData;
        // Pad to 512-byte block boundary
        auto remainder = fileData.length % TAR_BLOCK_SIZE;
        if (remainder > 0) {
            auto padding = TAR_BLOCK_SIZE - remainder;
            _buf.length += padding;
        }
    }

    private static void computeChecksum(ref ubyte[TAR_BLOCK_SIZE] header) {
        // Fill checksum field with spaces for computation
        header[148 .. 156] = ' ';

        uint sum = 0;
        foreach (b; header)
            sum += b;

        writeOctal(header[148 .. 156], sum);
        header[155] = ' '; // Traditional: terminated by null and space
    }

    static void testWriteOctal(ubyte[] field, ulong value) {
        writeOctal(field, value);
    }

    private static void writeOctal(ubyte[] field, ulong value) {
        import darkarchive.exception : DarkArchiveException;

        auto len = field.length;
        // Max representable: (len-1) octal digits. Check before writing.
        auto maxDigits = len - 1; // last byte is null terminator
        ulong maxValue = 1;
        foreach (_; 0 .. maxDigits)
            maxValue *= 8;
        maxValue -= 1; // e.g. 12 bytes → 11 digits → max 0x1FFFFFFFF (8589934591)

        if (value > maxValue)
            throw new DarkArchiveException("TAR: value too large for octal field");

        field[] = '0';
        field[len - 1] = 0; // null terminator

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
        // Record format: "<length> <content>"
        // Length includes the length field itself + space + content
        // Need to compute iteratively since length of length varies
        auto contentLen = content.length;
        size_t totalLen = contentLen + 2; // minimum: "N " where N is 1 digit
        while (true) {
            auto lenStr = formatDecimal(totalLen);
            auto actual = lenStr.length + 1 + contentLen; // lenStr + space + content
            if (actual == totalLen) break;
            totalLen = actual;
            if (totalLen > contentLen + 20) break; // safety
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

    /// Write tar round-trip with addBuffer
    @("tar write: round-trip with addBuffer")
    unittest {
        auto writer = TarWriter.create();
        writer
            .addBuffer("hello.txt", cast(const(ubyte)[]) "Hello World!")
            .addBuffer("sub/nested.txt", cast(const(ubyte)[]) "Nested content");

        auto reader = TarReader(writer.data);
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

    /// Write directory
    @("tar write: addDirectory")
    unittest {
        auto writer = TarWriter.create();
        writer.addDirectory("mydir");

        auto reader = TarReader(writer.data);
        foreach (entry; reader.entries) {
            if (entry.pathname == "mydir/") {
                entry.isDir.shouldBeTrue;
            }
        }
    }

    /// Write symlink
    @("tar write: addSymlink")
    unittest {
        auto writer = TarWriter.create();
        writer.addSymlink("link.txt", "target.txt");

        auto reader = TarReader(writer.data);
        foreach (entry; reader.entries) {
            if (entry.pathname == "link.txt") {
                entry.isSymlink.shouldBeTrue;
                entry.symlinkTarget.shouldEqual("target.txt");
            }
        }
    }

    /// Long UTF-8 pathname via pax
    @("tar write: long UTF-8 pathname via pax extended header")
    unittest {
        import std.array : replicate;
        auto longName = "深层目录/" ~ "子目录/".replicate(20) ~ "文件.txt";

        auto writer = TarWriter.create();
        writer.addBuffer(longName, cast(const(ubyte)[]) "pax content");

        auto reader = TarReader(writer.data);
        foreach (entry; reader.entries) {
            if (entry.pathname == longName) {
                reader.readText().shouldEqual("pax content");
                return;
            }
        }
        assert(false, "pax entry not found");
    }

    /// Method chaining
    @("tar write: method chaining")
    unittest {
        auto writer = TarWriter.create();
        writer
            .addBuffer("a.txt", cast(const(ubyte)[]) "A")
            .addBuffer("b.txt", cast(const(ubyte)[]) "B")
            .addDirectory("dir");

        auto reader = TarReader(writer.data);
        int count;
        foreach (entry; reader.entries)
            count++;
        count.shouldEqual(3);
    }

    /// tar.gz round-trip
    @("tar.gz write: round-trip via gzipCompress + gunzip")
    unittest {
        import darkarchive.gzip : gunzip;

        auto writer = TarWriter.create();
        writer
            .addBuffer("file-a.txt", cast(const(ubyte)[]) "Content A")
            .addBuffer("file-b.txt", cast(const(ubyte)[]) "Content B");

        auto gzData = gzipCompress(writer.data);
        assert(gzData.length > 0);

        auto tarData = gunzip(gzData);
        auto reader = TarReader(tarData);
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

    /// Written tar is readable
    @("tar write: single file, verify content")
    unittest {
        auto writer = TarWriter.create();
        writer.addBuffer("test.txt", cast(const(ubyte)[]) "tar file content");

        auto reader = TarReader(writer.data);
        foreach (entry; reader.entries) {
            if (entry.pathname == "test.txt") {
                reader.readText().shouldEqual("tar file content");
                return;
            }
        }
        assert(false, "entry not found");
    }

    // -------------------------------------------------------------------
    // Security / edge-case tests
    // -------------------------------------------------------------------

    /// Written tar.gz readable by system tar
    @("tar interop: written tar.gz readable by system tar")
    unittest {
        import darkarchive.gzip : gunzip;
        import std.file : write, remove, exists;
        import std.process : execute;

        auto outPath = "test-data/test-d-to-tar.tar.gz";
        scope(exit) if (exists(outPath)) remove(outPath);

        auto writer = TarWriter.create();
        writer
            .addBuffer("hello.txt", cast(const(ubyte)[]) "Hello from D tar!\n")
            .addDirectory("mydir");
        auto gzData = gzipCompress(writer.data);
        write(outPath, gzData);

        // Verify with system tar
        auto result = execute(["tar", "tzf", outPath]);
        assert(result.status == 0, "tar failed: " ~ result.output);
        import std.algorithm : canFind;
        assert(result.output.canFind("hello.txt"), "tar listing missing hello.txt");
    }

    /// writeOctal must throw when value doesn't fit in field
    @("tar write security: octal overflow in size field throws")
    unittest {
        import darkarchive.exception : DarkArchiveException;

        // The size field in ustar is 12 bytes (11 octal digits + null).
        // Max value: octal 77777777777 = 8,589,934,591 (~8GB).
        // A file larger than that must trigger pax extended header for size,
        // or throw if it can't be represented.

        // Directly test writeOctal with a value that overflows 12-byte field
        ubyte[12] field;
        bool caught;
        try {
            TarWriter.testWriteOctal(field[], ulong.max);
        } catch (DarkArchiveException e) {
            caught = true;
        }
        caught.shouldBeTrue;

        // Normal value should work
        TarWriter.testWriteOctal(field[], 420);
        // Verify it wrote something (field[0] should not be null)
        assert(field[0] == '0' || (field[0] >= '1' && field[0] <= '7'));
    }
}
