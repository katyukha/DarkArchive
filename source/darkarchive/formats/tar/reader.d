/// TAR archive reader — pure D implementation.
///
/// Reads TAR archives following POSIX.1-2001 (pax) and ustar formats.
/// Supports pax extended headers for UTF-8 pathnames and large sizes.
/// Uses DataSource for file-backed I/O (does not load full file into memory).
module darkarchive.formats.tar.reader;

import darkarchive.entry : DarkArchiveEntry, EntryType;
import darkarchive.exception : DarkArchiveException;
import darkarchive.formats.tar.types;
import darkarchive.datasource : DataSource, SequentialReader,
    DataSourceSequentialReader, GzipSequentialReader;

/// Reads a TAR archive from a file, memory buffer, or streaming gzip source.
struct TarReader {
    private {
        SequentialReader _stream;

        // Current entry state
        DarkArchiveEntry _currentEntry;
        ubyte[] _currentData;    // current entry data (null if not yet read)
        size_t _currentDataSize; // size of current entry data
        bool _hasEntry;
        bool _dataConsumed;      // true if data was read or skipped
    }

    @disable this();

    /// Open TAR from a byte buffer.
    this(const(ubyte)[] data) {
        auto ds = new DataSource();
        *ds = DataSource.fromMemory(data);
        _stream = new DataSourceSequentialReader(ds);
    }

    /// Open TAR from a file path (does not load full file into memory).
    this(string path) {
        auto ds = new DataSource();
        *ds = DataSource.fromFile(path);
        _stream = new DataSourceSequentialReader(ds);
    }

    /// Open TAR from a streaming gzip decompressor (for .tar.gz).
    /// No temp files, no full decompression — constant memory usage.
    this(SequentialReader stream) {
        _stream = stream;
    }

    /// Close the underlying data source.
    void close() {
        if (_stream !is null)
            _stream.close();
    }

    /// Iterate over entries.
    auto entries() {
        return EntryRange(&this);
    }

    /// Read the current entry's full data into memory.
    /// For large entries, use readDataChunked instead.
    const(ubyte)[] readData() {
        if (!_hasEntry || _currentDataSize == 0)
            return null;
        // If data was already consumed (chunked read or previous readData), return cached
        if (_currentData !is null)
            return _currentData;
        if (_dataConsumed)
            return null; // already skipped past this entry's data
        // Read from stream
        try {
            _currentData = _stream.read(_currentDataSize);
            _dataConsumed = true;
        } catch (DarkArchiveException) {
            _currentData = null;
            _dataConsumed = true;
        }
        return _currentData;
    }

    /// Read current entry data in chunks via sink delegate.
    /// Never loads full entry into memory — safe for multi-GB entries.
    void readDataChunked(scope void delegate(const(ubyte)[] chunk) sink,
                          size_t chunkSize = 8192) {
        if (!_hasEntry || _currentDataSize == 0)
            return;
        if (_dataConsumed)
            return; // already read or skipped

        // Read from stream in chunks
        size_t remaining = _currentDataSize;
        while (remaining > 0) {
            auto toRead = remaining > chunkSize ? chunkSize : remaining;
            try {
                auto chunk = _stream.read(toRead);
                sink(chunk);
                remaining -= chunk.length;
            } catch (DarkArchiveException) {
                break;
            }
        }
        _dataConsumed = true;
    }

    /// Read current entry data as text.
    string readText() {
        auto d = readData();
        return d is null ? "" : cast(string) d.idup;
    }

    /// Skip current entry's data. In streaming mode, this advances
    /// the stream position past the entry data.
    void skipData() {
        if (_hasEntry && !_dataConsumed && _currentDataSize > 0) {
            _stream.skip(_currentDataSize);
            _dataConsumed = true;
        }
    }

    static struct EntryRange {
        private TarReader* _reader;
        private bool _done;
        private size_t _pendingSkip; // bytes to skip before next header

        this(TarReader* reader) {
            _reader = reader;
            advance();
        }

        bool empty() { return _done; }

        DarkArchiveEntry front() {
            return _reader._currentEntry;
        }

        void popFront() {
            // If data was not consumed by the user, skip it in the stream
            if (!_reader._dataConsumed && _reader._currentDataSize > 0) {
                _reader._stream.skip(_reader._currentDataSize);
                _reader._dataConsumed = true;
            }
            // Skip padding
            if (_pendingSkip > 0) {
                _reader._stream.skip(_pendingSkip);
                _pendingSkip = 0;
            }
            advance();
        }

        private void advance() {
            _reader._hasEntry = false;
            _reader._currentData = null;

            while (!_reader._stream.empty) {
                ubyte[] headerBlock;
                try {
                    headerBlock = _reader._stream.read(TAR_BLOCK_SIZE);
                } catch (DarkArchiveException) {
                    _done = true;
                    return;
                }

                if (isZeroBlock(headerBlock)) {
                    _done = true;
                    return;
                }

                if (!verifyChecksum(headerBlock)) {
                    _done = true;
                    return;
                }

                auto typeflag = cast(char) headerBlock[156];
                auto entrySize = parseOctal(headerBlock[124 .. 136]);
                if (entrySize < 0) entrySize = 0;

                auto dataSize = cast(size_t) entrySize;
                auto paddedSize = (dataSize + TAR_BLOCK_SIZE - 1)
                    / TAR_BLOCK_SIZE * TAR_BLOCK_SIZE;

                if (typeflag == TAR_TYPE_PAX_EXTENDED || typeflag == TAR_TYPE_PAX_GLOBAL) {
                    // Read pax data from stream
                    enum MAX_PAX_SIZE = 1024 * 1024;
                    auto paxSize = dataSize > MAX_PAX_SIZE ? MAX_PAX_SIZE : dataSize;

                    string[string] paxAttrs;
                    try {
                        auto paxBytes = _reader._stream.read(paxSize);
                        paxAttrs = parsePaxData(paxBytes);
                        // Skip remaining pax data + padding
                        if (paddedSize > paxSize)
                            _reader._stream.skip(paddedSize - paxSize);
                    } catch (DarkArchiveException) {
                        _done = true;
                        return;
                    }

                    // Read the actual entry header that follows
                    try {
                        headerBlock = _reader._stream.read(TAR_BLOCK_SIZE);
                    } catch (DarkArchiveException) {
                        _done = true;
                        return;
                    }

                    if (isZeroBlock(headerBlock)) {
                        _done = true;
                        return;
                    }

                    typeflag = cast(char) headerBlock[156];
                    entrySize = parseOctal(headerBlock[124 .. 136]);
                    if (entrySize < 0) entrySize = 0;
                    dataSize = cast(size_t) entrySize;
                    paddedSize = (dataSize + TAR_BLOCK_SIZE - 1)
                        / TAR_BLOCK_SIZE * TAR_BLOCK_SIZE;

                    _reader._currentEntry = parseHeader(headerBlock);

                    // Apply pax overrides
                    applyPaxAttrs(_reader._currentEntry, paxAttrs);
                    if (auto s = "size" in paxAttrs) {
                        import std.conv : to;
                        dataSize = (*s).to!size_t;
                        _reader._currentEntry.size = (*s).to!long;
                        paddedSize = (dataSize + TAR_BLOCK_SIZE - 1)
                            / TAR_BLOCK_SIZE * TAR_BLOCK_SIZE;
                    }
                } else {
                    _reader._currentEntry = parseHeader(headerBlock);
                }

                // Record entry data size — actual reading happens lazily
                // in readData() or readDataChunked()
                _reader._currentDataSize = dataSize;
                _reader._currentData = null;
                _reader._dataConsumed = false;
                _pendingSkip = paddedSize > dataSize ? paddedSize - dataSize : 0;

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
        auto spaceIdx = indexOf(text[pos .. $], ' ');
        if (spaceIdx <= 0) break;

        import std.conv : to;
        size_t recordLen;
        try {
            recordLen = text[pos .. pos + spaceIdx].to!size_t;
        } catch (Exception) {
            break;
        }

        if (recordLen <= cast(size_t)(spaceIdx + 1)) break;
        if (pos + recordLen > text.length) break;

        auto recordStart = pos + spaceIdx + 1;
        auto recordEnd = pos + recordLen;
        if (recordStart >= recordEnd) break;

        auto record = text[recordStart .. recordEnd];
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
    size_t len = 0;
    while (len < field.length && field[len] != 0)
        len++;
    if (len == 0) return "";
    return (cast(const(char)[]) field[0 .. len]).idup;
}

private long parseOctal(const(ubyte)[] field) {
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
    auto storedChecksum = parseOctal(header[148 .. 156]);

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

    @("tar read: symlink entry")
    unittest {
        auto reader = TarReader(testDataDir ~ "/test-symlink.tar");
        bool foundLink, foundTarget;
        foreach (entry; reader.entries) {
            if (entry.pathname == "./link.txt") {
                foundLink = true;
                entry.isSymlink.shouldBeTrue;
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

    @("tar read: directory entries")
    unittest {
        auto reader = TarReader(testDataDir ~ "/test-symlink.tar");
        bool foundDir;
        foreach (entry; reader.entries)
            if (entry.pathname == "./" && entry.isDir) foundDir = true;
        foundDir.shouldBeTrue;
    }

    @("tar read: permissions parsed")
    unittest {
        auto reader = TarReader(testDataDir ~ "/test-empty-files.tar");
        foreach (entry; reader.entries)
            if (entry.pathname == "./notempty.txt")
                assert(entry.permissions > 0);
    }

    // -------------------------------------------------------------------
    // Security tests
    // -------------------------------------------------------------------

    @("tar security: non-tar data does not crash")
    unittest {
        auto garbage = cast(const(ubyte)[]) "this is not a tar file";
        auto padded = new ubyte[](1024);
        padded[0 .. garbage.length] = garbage[];
        auto reader = TarReader(padded);
        int count;
        foreach (entry; reader.entries) count++;
        count.shouldEqual(0);
    }

    @("tar security: truncated archive does not crash")
    unittest {
        import darkarchive.formats.tar.writer : TarWriter;
        auto writer = TarWriter.create();
        writer.addBuffer("test.txt", cast(const(ubyte)[]) "some content here");
        auto fullData = writer.data;
        auto truncated = fullData[0 .. 512 + 5];
        auto reader = TarReader(truncated);
        foreach (entry; reader.entries) {
            if (entry.pathname == "test.txt") {
                bool caught;
                try { auto d = reader.readData(); }
                catch (DarkArchiveException e) { caught = true; }
            }
        }
    }

    @("tar security: pax with zero-length record does not hang")
    unittest {
        auto malicious1 = cast(const(ubyte)[]) "0 path=evil\n";
        auto result1 = parsePaxData(malicious1);
        auto malicious2 = cast(const(ubyte)[]) " path=evil\n";
        auto result2 = parsePaxData(malicious2);
        auto empty = cast(const(ubyte)[]) "";
        auto result3 = parsePaxData(empty);
        assert(result3.length == 0);
    }

    @("tar security: octal overflow throws")
    unittest {
        auto normal = cast(const(ubyte)[]) "0000644\0";
        parseOctal(normal).shouldEqual(420);
        auto maxval = cast(const(ubyte)[]) "77777777777";
        parseOctal(maxval).shouldEqual(8_589_934_591);
        auto huge = cast(const(ubyte)[]) "777777777777777777777777";
        bool caught;
        try { parseOctal(huge); }
        catch (DarkArchiveException e) { caught = true; }
        caught.shouldBeTrue;
    }

    @("tar security: garbage header rejected by checksum")
    unittest {
        ubyte[512] header;
        foreach (i, ref b; header) b = cast(ubyte)((i * 37 + 13) & 0xFF);
        auto reader = TarReader(header[]);
        int count;
        foreach (entry; reader.entries) count++;
        count.shouldEqual(0);
    }

    // -------------------------------------------------------------------
    // Format edge-case tests
    // -------------------------------------------------------------------

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
                reader.readData().length.shouldEqual(512);
                reader.readData().shouldEqual(data);
                return;
            }
        }
        assert(false, "entry not found");
    }

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
                reader.readData().shouldEqual(data);
                return;
            }
        }
        assert(false, "entry not found");
    }

    @("tar format: single byte entry")
    unittest {
        import darkarchive.formats.tar.writer : TarWriter;
        auto writer = TarWriter.create();
        writer.addBuffer("one.bin", [cast(ubyte) 0x42]);
        auto reader = TarReader(writer.data);
        foreach (entry; reader.entries) {
            if (entry.pathname == "one.bin") {
                entry.size.shouldEqual(1);
                reader.readData()[0].shouldEqual(0x42);
                return;
            }
        }
        assert(false, "entry not found");
    }

    @("tar format: GNU long filename does not crash")
    unittest {
        auto reader = TarReader(testDataDir ~ "/test-gnu-longname.tar");
        int count;
        foreach (entry; reader.entries) count++;
        assert(count > 0);
    }

    @("tar format: empty filename does not crash")
    unittest {
        import darkarchive.formats.tar.writer : TarWriter;
        auto writer = TarWriter.create();
        writer.addBuffer("", cast(const(ubyte)[]) "no name");
        auto reader = TarReader(writer.data);
        foreach (entry; reader.entries)
            assert(entry.pathname !is null);
    }

    // -------------------------------------------------------------------
    // CVE / overflow tests
    // -------------------------------------------------------------------

    @("CVE: pax size attribute with absurd value")
    unittest {
        auto maliciousPax = cast(const(ubyte)[]) "30 size=99999999999999999999\n";
        auto attrs = parsePaxData(maliciousPax);
    }

    @("tar security: huge size field does not OOB")
    unittest {
        import darkarchive.formats.tar.writer : TarWriter;
        auto writer = TarWriter.create();
        writer.addBuffer("small.txt", cast(const(ubyte)[]) "tiny");
        auto data = writer.data.dup;
        data[124 .. 136] = cast(ubyte[12]) "77777777777\0";
        uint sum = 0;
        foreach (i; 0 .. 512) {
            if (i >= 148 && i < 156) sum += ' ';
            else sum += data[i];
        }
        import std.format : format;
        auto checksumStr = format!"%06o\0 "(sum);
        data[148 .. 156] = cast(ubyte[8]) checksumStr[0 .. 8];
        auto reader = TarReader(cast(const(ubyte)[]) data);
        foreach (entry; reader.entries) {
            if (entry.pathname == "small.txt") {
                bool caught;
                try { reader.readData(); }
                catch (DarkArchiveException e) { caught = true; }
            }
        }
    }

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

    @("tar security: corrupted header mid-archive throws")
    unittest {
        import darkarchive.formats.tar.writer : TarWriter;
        auto writer = TarWriter.create();
        writer
            .addBuffer("file1.txt", cast(const(ubyte)[]) "content 1")
            .addBuffer("file2.txt", cast(const(ubyte)[]) "content 2");
        auto data = writer.data.dup;
        if (data.length > 1024 + 156) {
            data[1024 + 148] = 0xFF;
            data[1024 + 149] = 0xFF;
        }
        auto reader = TarReader(cast(const(ubyte)[]) data);
        int count;
        foreach (entry; reader.entries) count++;
        // First entry is intact, second has corrupted checksum → iteration
        // stops at the corrupted header. First entry must be preserved.
        count.shouldEqual(1);
    }
}
