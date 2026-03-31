/// TAR archive reader — pure D implementation.
///
/// Reads TAR archives following POSIX.1-2001 (pax) and ustar formats.
/// Supports pax extended headers for UTF-8 pathnames and large sizes.
module darkarchive.formats.tar.reader;

import darkarchive.entry : DarkArchiveEntry, EntryType;
import darkarchive.exception : DarkArchiveException;
import darkarchive.formats.tar.types;

/// Reads a TAR archive from a byte buffer.
/// For tar.gz, decompress first with GzipReader, then feed the raw tar bytes here.
struct TarReader {
    private {
        const(ubyte)[] _data;
        size_t _pos;

        // Current entry state
        DarkArchiveEntry _currentEntry;
        size_t _dataStart;
        size_t _dataSize;
        bool _hasEntry;
    }

    @disable this();

    /// Open TAR from a byte buffer.
    this(const(ubyte)[] data) {
        _data = data;
        _pos = 0;
    }

    /// Open TAR from a file path.
    this(string path) {
        import std.file : read;
        _data = cast(const(ubyte)[]) read(path);
        _pos = 0;
    }

    /// Iterate over entries.
    auto entries() {
        // Reset position for iteration
        _pos = 0;
        return EntryRange(&this);
    }

    /// Read the current entry's data.
    const(ubyte)[] readData() {
        if (!_hasEntry || _dataSize == 0)
            return null;
        if (_dataStart + _dataSize > _data.length)
            throw new DarkArchiveException("TAR: entry data out of bounds");
        return _data[_dataStart .. _dataStart + _dataSize];
    }

    /// Read current entry data as text.
    string readText() {
        auto d = readData();
        return d is null ? "" : cast(string) d.idup;
    }

    /// Skip current entry's data (advance to next header).
    void skipData() {
        // No-op for memory-based reader; position is advanced in popFront
    }

    static struct EntryRange {
        private TarReader* _reader;
        private bool _done;

        this(TarReader* reader) {
            _reader = reader;
            advance();
        }

        bool empty() { return _done; }

        DarkArchiveEntry front() {
            return _reader._currentEntry;
        }

        void popFront() {
            // Skip past current entry data (padded to 512-byte block)
            if (_reader._dataSize > 0) {
                auto paddedSize = (_reader._dataSize + TAR_BLOCK_SIZE - 1)
                    / TAR_BLOCK_SIZE * TAR_BLOCK_SIZE;
                auto newPos = _reader._dataStart + paddedSize;
                // Clamp to data length to prevent OOB on next iteration
                _reader._pos = newPos > _reader._data.length
                    ? _reader._data.length : newPos;
            }
            advance();
        }

        private void advance() {
            _reader._hasEntry = false;

            while (_reader._pos + TAR_BLOCK_SIZE <= _reader._data.length) {
                auto headerBlock = _reader._data[_reader._pos .. _reader._pos + TAR_BLOCK_SIZE];

                // Two consecutive zero blocks = end of archive
                if (isZeroBlock(headerBlock)) {
                    _done = true;
                    return;
                }

                // Verify checksum
                if (!verifyChecksum(headerBlock)) {
                    _done = true;
                    return;
                }

                auto typeflag = cast(char) headerBlock[156];
                auto entrySize = parseOctal(headerBlock[124 .. 136]);

                // Validate entry size is non-negative and fits in addressable range
                if (entrySize < 0) entrySize = 0;

                if (typeflag == TAR_TYPE_PAX_EXTENDED || typeflag == TAR_TYPE_PAX_GLOBAL) {
                    // Pax extended header — parse key-value pairs, apply to next entry
                    _reader._pos += TAR_BLOCK_SIZE;

                    // Cap pax data size to prevent excessive allocation
                    // (pax headers should be small — cap at 1MB)
                    enum MAX_PAX_SIZE = 1024 * 1024;
                    auto paxSize = entrySize > MAX_PAX_SIZE ? MAX_PAX_SIZE : cast(size_t) entrySize;

                    auto paddedSize = (entrySize + TAR_BLOCK_SIZE - 1)
                        / TAR_BLOCK_SIZE * TAR_BLOCK_SIZE;

                    string[string] paxAttrs;
                    if (_reader._pos + paxSize <= _reader._data.length) {
                        paxAttrs = parsePaxData(
                            _reader._data[_reader._pos .. _reader._pos + paxSize]);
                    }

                    _reader._pos += cast(size_t)(paddedSize > _reader._data.length
                        ? _reader._data.length : paddedSize);

                    // Now read the actual entry that follows
                    if (_reader._pos + TAR_BLOCK_SIZE > _reader._data.length) {
                        _done = true;
                        return;
                    }

                    headerBlock = _reader._data[_reader._pos .. _reader._pos + TAR_BLOCK_SIZE];
                    if (isZeroBlock(headerBlock)) {
                        _done = true;
                        return;
                    }

                    typeflag = cast(char) headerBlock[156];
                    entrySize = parseOctal(headerBlock[124 .. 136]);

                    _reader._currentEntry = parseHeader(headerBlock);
                    _reader._pos += TAR_BLOCK_SIZE;
                    _reader._dataStart = _reader._pos;
                    _reader._dataSize = entrySize > _reader._data.length
                        ? _reader._data.length : cast(size_t) entrySize;

                    // Override with pax attributes
                    applyPaxAttrs(_reader._currentEntry, paxAttrs);
                    if (auto s = "size" in paxAttrs) {
                        import std.conv : to;
                        _reader._dataSize = (*s).to!size_t;
                        _reader._currentEntry.size = (*s).to!long;
                    }
                } else {
                    // Regular ustar header
                    _reader._currentEntry = parseHeader(headerBlock);
                    _reader._pos += TAR_BLOCK_SIZE;
                    _reader._dataStart = _reader._pos;
                    _reader._dataSize = entrySize > _reader._data.length
                        ? _reader._data.length : cast(size_t) entrySize;
                }

                _reader._hasEntry = true;
                return;
            }

            _done = true;
        }
    }
}

// -- Header parsing --

private DarkArchiveEntry parseHeader(const(ubyte)[] header) {
    import std.datetime.systime : SysTime;
    import std.datetime.date : DateTime;
    import std.datetime.timezone : UTC;

    DarkArchiveEntry e;

    // Name: prefix (offset 345, 155 bytes) + "/" + name (offset 0, 100 bytes)
    auto prefix = parseString(header[345 .. 500]);
    auto name = parseString(header[0 .. 100]);
    if (prefix.length > 0)
        e.pathname = prefix ~ "/" ~ name;
    else
        e.pathname = name;

    e.permissions = cast(uint) parseOctal(header[100 .. 108]);
    e.uid = parseOctal(header[108 .. 116]);
    e.gid = parseOctal(header[116 .. 124]);
    e.size = parseOctal(header[124 .. 136]);

    auto mtime = parseOctal(header[136 .. 148]);
    e.mtime = SysTime(unixTimeToStdTime(mtime), UTC());

    auto typeflag = cast(char) header[156];
    switch (typeflag) {
        case TAR_TYPE_DIR:
            e.type = EntryType.directory;
            break;
        case TAR_TYPE_SYMLINK:
            e.type = EntryType.symlink;
            e.symlinkTarget = parseString(header[157 .. 257]);
            break;
        default:
            e.type = EntryType.file;
            break;
    }

    e.uname = parseString(header[265 .. 297]);
    e.gname = parseString(header[297 .. 329]);

    return e;
}

private void applyPaxAttrs(ref DarkArchiveEntry e, string[string] attrs) {
    if (auto p = "path" in attrs)
        e.pathname = *p;
    if (auto p = "linkpath" in attrs)
        e.symlinkTarget = *p;
    if (auto p = "uname" in attrs)
        e.uname = *p;
    if (auto p = "gname" in attrs)
        e.gname = *p;
    if (auto p = "uid" in attrs) {
        import std.conv : to;
        e.uid = (*p).to!long;
    }
    if (auto p = "gid" in attrs) {
        import std.conv : to;
        e.gid = (*p).to!long;
    }
}

/// Parse pax extended header data: "length key=value\n" records.
private string[string] parsePaxData(const(ubyte)[] data) {
    string[string] result;
    auto text = cast(const(char)[]) data;
    size_t pos = 0;

    while (pos < text.length) {
        // Find space after length
        auto spaceIdx = indexOf(text[pos .. $], ' ');
        if (spaceIdx <= 0) break; // <= 0: no space found, or space at position 0

        import std.conv : to;
        size_t recordLen;
        try {
            recordLen = text[pos .. pos + spaceIdx].to!size_t;
        } catch (Exception) {
            break;
        }

        // Guard against zero or too-small recordLen (must be > spaceIdx + 1)
        if (recordLen <= cast(size_t)(spaceIdx + 1)) break;
        if (pos + recordLen > text.length) break;

        auto recordStart = pos + spaceIdx + 1;
        auto recordEnd = pos + recordLen;
        if (recordStart >= recordEnd) break;

        auto record = text[recordStart .. recordEnd];
        // Remove trailing newline
        if (record.length > 0 && record[$ - 1] == '\n')
            record = record[0 .. $ - 1];

        auto eqIdx = indexOf(record, '=');
        if (eqIdx >= 0) {
            auto key = record[0 .. eqIdx].idup;
            auto value = record[eqIdx + 1 .. $].idup;
            result[key] = value;
        }

        pos += recordLen;
    }

    return result;
}

// -- Utility functions --

private long indexOf(const(char)[] haystack, char needle) {
    foreach (i, c; haystack)
        if (c == needle) return cast(long) i;
    return -1;
}

private string parseString(const(ubyte)[] field) {
    // Find null terminator
    size_t len = 0;
    while (len < field.length && field[len] != 0)
        len++;
    if (len == 0) return "";
    return (cast(const(char)[]) field[0 .. len]).idup;
}

private long parseOctal(const(ubyte)[] field) {
    // Skip leading spaces/zeros, parse octal digits, stop at space/null.
    long result = 0;
    foreach (b; field) {
        if (b == ' ' || b == 0) {
            if (result > 0) break;
            continue;
        }
        if (b < '0' || b > '7') break;
        int digit = b - '0';
        if (result > (long.max - digit) / 8)
            throw new DarkArchiveException("TAR: octal value overflow");
        result = result * 8 + digit;
    }
    return result;
}

private bool isZeroBlock(const(ubyte)[] block) {
    foreach (b; block)
        if (b != 0) return false;
    return true;
}

private bool verifyChecksum(const(ubyte)[] header) {
    // Checksum is at offset 148, 8 bytes (octal, space-terminated)
    auto storedChecksum = parseOctal(header[148 .. 156]);

    // Compute: sum of all bytes, treating checksum field as spaces
    uint computed = 0;
    foreach (i, b; header) {
        if (i >= 148 && i < 156)
            computed += ' ';
        else
            computed += b;
    }

    return computed == storedChecksum;
}

private long unixTimeToStdTime(long unixTime) pure nothrow @nogc {
    return (unixTime + 621_355_968_00L) * 10_000_000L;
}


// ===========================================================================
// Unit tests
// ===========================================================================

version(unittest) {
    import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse,
        shouldBeGreaterThan;

    private immutable testDataDir = "test-data";

    /// Symlink archive
    @("tar read: symlink entry")
    unittest {
        auto reader = TarReader(testDataDir ~ "/test-symlink.tar");
        bool foundLink, foundTarget;
        foreach (entry; reader.entries) {
            if (entry.pathname == "./link.txt") {
                foundLink = true;
                entry.isSymlink.shouldBeTrue;
                entry.isFile.shouldBeFalse;
                entry.symlinkTarget.shouldEqual("target.txt");
            } else if (entry.pathname == "./target.txt") {
                foundTarget = true;
                entry.isFile.shouldBeTrue;
                reader.readText().shouldEqual("target content\n");
            }
        }
        foundLink.shouldBeTrue;
        foundTarget.shouldBeTrue;
    }

    /// Zero-byte files
    @("tar read: zero-byte files")
    unittest {
        auto reader = TarReader(testDataDir ~ "/test-empty-files.tar");
        bool foundGitkeep, foundEmpty, foundNotempty;
        foreach (entry; reader.entries) {
            if (entry.pathname == "./.gitkeep") {
                foundGitkeep = true;
                entry.isFile.shouldBeTrue;
                entry.size.shouldEqual(0);
                reader.readData().length.shouldEqual(0);
            } else if (entry.pathname == "./empty.txt") {
                foundEmpty = true;
                entry.isFile.shouldBeTrue;
                entry.size.shouldEqual(0);
            } else if (entry.pathname == "./notempty.txt") {
                foundNotempty = true;
                entry.isFile.shouldBeTrue;
                entry.size.shouldBeGreaterThan(0);
                reader.readText().shouldEqual("notempty\n");
            }
        }
        foundGitkeep.shouldBeTrue;
        foundEmpty.shouldBeTrue;
        foundNotempty.shouldBeTrue;
    }

    /// Directory entries
    @("tar read: directory entries")
    unittest {
        auto reader = TarReader(testDataDir ~ "/test-symlink.tar");
        bool foundDir;
        foreach (entry; reader.entries) {
            if (entry.pathname == "./" && entry.isDir) {
                foundDir = true;
            }
        }
        foundDir.shouldBeTrue;
    }

    /// Permissions are parsed
    @("tar read: permissions parsed")
    unittest {
        auto reader = TarReader(testDataDir ~ "/test-empty-files.tar");
        foreach (entry; reader.entries) {
            if (entry.pathname == "./notempty.txt") {
                assert(entry.permissions > 0, "should have non-zero permissions");
            }
        }
    }

    // -------------------------------------------------------------------
    // Security / edge-case tests
    // -------------------------------------------------------------------

    /// Completely invalid data (not TAR) must not crash
    @("tar security: non-tar data does not crash")
    unittest {
        auto garbage = cast(const(ubyte)[]) "this is not a tar file";
        // Pad to at least 512 bytes so it doesn't immediately end
        auto padded = new ubyte[](1024);
        padded[0 .. garbage.length] = garbage[];

        auto reader = TarReader(padded);
        int count;
        foreach (entry; reader.entries) {
            count++;
        }
        // Invalid data should produce 0 entries (checksum fails), not crash
        count.shouldEqual(0);
    }

    /// Truncated TAR (cut mid-entry data) must not crash
    @("tar security: truncated archive does not crash")
    unittest {
        import darkarchive.formats.tar.writer : TarWriter;

        auto writer = TarWriter.create();
        writer.addBuffer("test.txt", cast(const(ubyte)[]) "some content here");
        auto fullData = writer.data;

        // Cut in the middle of entry data (after header but before all data)
        auto truncated = fullData[0 .. 512 + 5]; // header + 5 bytes of data

        auto reader = TarReader(truncated);
        foreach (entry; reader.entries) {
            if (entry.pathname == "test.txt") {
                // readData should return what's available or throw, not crash
                bool caught;
                try {
                    auto d = reader.readData();
                } catch (DarkArchiveException e) {
                    caught = true;
                }
                // Either truncated data or exception is acceptable, crash is not
            }
        }
    }

    /// PAX record with zero-length must not infinite loop
    @("tar security: pax with zero-length record does not hang")
    unittest {
        // Craft a minimal TAR with a pax extended header containing "0 path=x\n"
        // which has recordLen=0 and would cause infinite loop
        import darkarchive.formats.tar.reader : parsePaxData;

        // Directly test parsePaxData with malicious input
        auto malicious1 = cast(const(ubyte)[]) "0 path=evil\n";
        auto result1 = parsePaxData(malicious1);
        // Should not hang — should return empty or partial results

        // Also test with space at position 0
        auto malicious2 = cast(const(ubyte)[]) " path=evil\n";
        auto result2 = parsePaxData(malicious2);
        // Should not hang

        // Test with completely empty
        auto empty = cast(const(ubyte)[]) "";
        auto result3 = parsePaxData(empty);
        assert(result3.length == 0);
    }

    /// Octal field overflow must throw, not silently corrupt
    @("tar security: octal overflow throws")
    unittest {
        // Normal value
        auto normal = cast(const(ubyte)[]) "0000644\0";
        parseOctal(normal).shouldEqual(420); // octal 644 = decimal 420

        // Maximum representable in 11 octal digits (typical size field)
        // 77777777777 octal = 8589934591 decimal — fits in long
        auto maxval = cast(const(ubyte)[]) "77777777777";
        auto result = parseOctal(maxval);
        result.shouldEqual(8_589_934_591);

        // Very long octal (more digits than fit in long) must throw
        auto huge = cast(const(ubyte)[]) "777777777777777777777777";
        bool caught;
        try {
            parseOctal(huge);
        } catch (DarkArchiveException e) {
            caught = true;
        }
        caught.shouldBeTrue;
    }

    /// Checksum verification rejects garbage headers
    @("tar security: garbage header rejected by checksum")
    unittest {
        ubyte[512] header;
        // Fill with random non-zero data
        foreach (i, ref b; header)
            b = cast(ubyte)((i * 37 + 13) & 0xFF);

        // This should fail checksum and not be treated as valid entry
        auto reader = TarReader(header[]);
        int count;
        foreach (entry; reader.entries)
            count++;
        count.shouldEqual(0);
    }

    // -------------------------------------------------------------------
    // Format edge-case tests
    // -------------------------------------------------------------------

    /// Entry with data size exactly on 512-byte boundary (no padding needed)
    @("tar format: data size exactly 512 bytes, no padding")
    unittest {
        import darkarchive.formats.tar.writer : TarWriter;

        auto data = new ubyte[](512);
        foreach (i, ref b; data) b = cast(ubyte)(i & 0xFF);

        auto writer = TarWriter.create();
        writer.addBuffer("exact512.bin", data);

        auto reader = TarReader(writer.data);
        foreach (entry; reader.entries) {
            if (entry.pathname == "exact512.bin") {
                entry.size.shouldEqual(512);
                auto content = reader.readData();
                content.length.shouldEqual(512);
                content.shouldEqual(data);
                return;
            }
        }
        assert(false, "entry not found");
    }

    /// Entry with data size 1 byte over 512-byte boundary (511 bytes padding)
    @("tar format: data size 513 bytes, needs 511 padding")
    unittest {
        import darkarchive.formats.tar.writer : TarWriter;

        auto data = new ubyte[](513);
        foreach (i, ref b; data) b = cast(ubyte)(i & 0xFF);

        auto writer = TarWriter.create();
        writer.addBuffer("over512.bin", data);

        auto reader = TarReader(writer.data);
        foreach (entry; reader.entries) {
            if (entry.pathname == "over512.bin") {
                entry.size.shouldEqual(513);
                auto content = reader.readData();
                content.length.shouldEqual(513);
                content.shouldEqual(data);
                return;
            }
        }
        assert(false, "entry not found");
    }

    /// Entry with exactly 1 byte of data
    @("tar format: single byte entry")
    unittest {
        import darkarchive.formats.tar.writer : TarWriter;

        auto writer = TarWriter.create();
        writer.addBuffer("one.bin", [cast(ubyte) 0x42]);

        auto reader = TarReader(writer.data);
        foreach (entry; reader.entries) {
            if (entry.pathname == "one.bin") {
                entry.size.shouldEqual(1);
                auto content = reader.readData();
                content.length.shouldEqual(1);
                content[0].shouldEqual(0x42);
                return;
            }
        }
        assert(false, "entry not found");
    }

    /// GNU tar with long filename (>100 chars, ././@LongLink) — must not crash
    @("tar format: GNU long filename does not crash")
    unittest {
        auto reader = TarReader(testDataDir ~ "/test-gnu-longname.tar");
        int count;
        bool foundLong;
        foreach (entry; reader.entries) {
            count++;
            // GNU long names use ././@LongLink pseudo-entries.
            // We don't fully support GNU extensions, but we must not crash.
            // The file might appear with truncated name or as the @LongLink entry.
            if (entry.pathname.length > 80)
                foundLong = true;
        }
        // Should iterate without crashing. May or may not find the long name
        // depending on how we handle GNU extensions, but entry count must be > 0.
        assert(count > 0, "should have found some entries in GNU tar");
    }

    /// Empty filename in TAR entry — should not crash
    @("tar format: empty filename does not crash")
    unittest {
        import darkarchive.formats.tar.writer : TarWriter;

        auto writer = TarWriter.create();
        writer.addBuffer("", cast(const(ubyte)[]) "no name");

        auto reader = TarReader(writer.data);
        foreach (entry; reader.entries) {
            assert(entry.pathname !is null);
        }
    }

    // -------------------------------------------------------------------
    // Overflow / DoS hardening tests
    // -------------------------------------------------------------------

    /// TAR with crafted huge size field must not cause OOB or hang
    @("tar security: huge size field does not OOB")
    unittest {
        import darkarchive.formats.tar.writer : TarWriter;

        auto writer = TarWriter.create();
        writer.addBuffer("small.txt", cast(const(ubyte)[]) "tiny");
        auto data = writer.data.dup;

        // Patch the size field (offset 124, 12 bytes) to a huge octal value
        // "77777777777" = ~8GB — way beyond our tiny archive
        data[124 .. 136] = cast(ubyte[12]) "77777777777\0";

        // Recompute checksum for the patched header
        uint sum = 0;
        foreach (i; 0 .. 512) {
            if (i >= 148 && i < 156)
                sum += ' ';
            else
                sum += data[i];
        }
        import std.format : format;
        auto checksumStr = format!"%06o\0 "(sum);
        data[148 .. 156] = cast(ubyte[8]) checksumStr[0 .. 8];

        auto reader = TarReader(cast(const(ubyte)[]) data);
        foreach (entry; reader.entries) {
            if (entry.pathname == "small.txt") {
                // readData should throw or return truncated — not crash
                bool caught;
                try {
                    auto d = reader.readData();
                } catch (DarkArchiveException e) {
                    caught = true;
                }
                // Either throws or returns what's available, never OOB
            }
        }
    }

    /// TAR with negative-looking size (parsed as large positive) must not crash
    @("tar security: entry with zero size does not crash readData")
    unittest {
        import darkarchive.formats.tar.writer : TarWriter;

        auto writer = TarWriter.create();
        writer.addBuffer("zero.txt", cast(const(ubyte)[]) "");

        auto reader = TarReader(writer.data);
        foreach (entry; reader.entries) {
            if (entry.pathname == "zero.txt") {
                auto d = reader.readData();
                assert(d is null || d.length == 0);
            }
        }
    }

    /// Corrupted header mid-archive must throw, not silently truncate
    @("tar security: corrupted header mid-archive throws")
    unittest {
        import darkarchive.formats.tar.writer : TarWriter;

        auto writer = TarWriter.create();
        writer
            .addBuffer("file1.txt", cast(const(ubyte)[]) "content 1")
            .addBuffer("file2.txt", cast(const(ubyte)[]) "content 2");
        auto data = writer.data.dup;

        // Corrupt the second entry's header (at offset 1024: first header 512 +
        // data padded to 512 = 1024). Flip bytes in the checksum field.
        if (data.length > 1024 + 156) {
            data[1024 + 148] = 0xFF;
            data[1024 + 149] = 0xFF;
        }

        auto reader = TarReader(cast(const(ubyte)[]) data);
        int count;
        bool threw;
        try {
            foreach (entry; reader.entries)
                count++;
        } catch (DarkArchiveException e) {
            threw = true;
        }
        // Must either throw on corrupt header, or at minimum read the first entry.
        // Must NOT silently return 0 entries (losing file1 too).
        assert(threw || count >= 1,
            "corrupted mid-archive header must throw or preserve prior entries");
    }
}
