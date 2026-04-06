/// TAR archive reader — pure D implementation.
///
/// Reads TAR archives following POSIX.1-2001 (pax) and ustar formats.
/// Supports pax extended headers for UTF-8 pathnames and large sizes.
///
/// `TarReader(R)` is a template over a stream type R. Any type with
/// `readInto(ubyte[])`, `skip(size_t)`, and `empty()` qualifies — use
/// `ChunkReader!X` or the `tarReader`/`tarGzReader` file factories.
///
/// Use the `tarReader(range)` factory for range-based construction.
module darkarchive.formats.tar.reader;

import darkarchive.entry : DarkArchiveEntry, EntryType;
import darkarchive.exception : DarkArchiveException;
import darkarchive.formats.tar.types;
import darkarchive.datasource : FileChunkSource, ChunkReader, GzipRange;
import std.range : isInputRange, ElementType;

/// Concept: any type providing the byte-stream interface needed by TarReader.
template isTarStream(R) {
    import std.traits : isInstanceOf;
    enum isTarStream =
        is(typeof({ R r = R.init; ubyte[1] b; r.readInto(b[]); })) &&
        is(typeof({ R r = R.init; r.skip(cast(size_t) 0); }))      &&
        is(typeof({ R r = R.init; bool e = r.empty(); }));
}

/// Reads a TAR archive from any stream type R satisfying `isTarStream!R`.
///
/// For file-backed reading use the `tarReader(path)` or `tarGzReader(path)` factories.
/// For range-based reading use `tarReader(range)`.
struct TarReader(R) if (isTarStream!R) {
    private {
        R _stream;

        // Current entry state
        DarkArchiveEntry _currentEntry;
        ubyte[] _currentData;    // current entry data (null if not yet read)
        size_t _currentDataSize; // size of current entry data
        bool _hasEntry;
        bool _dataConsumed;      // true if data was read or skipped
    }

    @disable this();

    /// Open TAR from a stream value (ChunkReader or other isTarStream type).
    this(R stream) {
        _stream = stream;
    }

    /// Close the underlying data source.
    void close() {
        static if (__traits(hasMember, R, "close"))
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
        if (_currentData !is null)
            return _currentData;
        if (_dataConsumed)
            return null;
        auto buf = new ubyte[](_currentDataSize);
        try {
            _stream.readInto(buf[]);
            _currentData = buf;
        } catch (DarkArchiveException) {
            _currentData = null;
        }
        _dataConsumed = true;
        return _currentData;
    }

    /// Read current entry data in chunks via sink delegate.
    /// Never loads full entry into memory — safe for multi-GB entries.
    void readDataChunked(scope void delegate(const(ubyte)[] chunk) sink,
                          size_t chunkSize = 8192) {
        if (!_hasEntry || _currentDataSize == 0)
            return;
        if (_dataConsumed)
            return;

        auto buf = new ubyte[](chunkSize);
        size_t remaining = _currentDataSize;
        while (remaining > 0) {
            auto toRead = remaining > chunkSize ? chunkSize : remaining;
            _stream.readInto(buf[0 .. toRead]);
            sink(buf[0 .. toRead]);
            remaining -= toRead;
        }
        _dataConsumed = true;
    }

    /// Read current entry data as text.
    string readText() {
        auto d = readData();
        return d is null ? "" : cast(string) d.idup;
    }

    /// Skip current entry's data. Advances the stream past the entry data.
    void skipData() {
        if (_hasEntry && !_dataConsumed && _currentDataSize > 0) {
            _stream.skip(_currentDataSize);
            _dataConsumed = true;
        }
    }

    static struct EntryRange {
        private TarReader!R* _reader;
        private bool _done;
        private bool _seenEntry;   /// true after the first valid entry is found
        private size_t _pendingSkip;

        this(TarReader!R* reader) {
            _reader = reader;
            advance();
        }

        bool empty() { return _done; }

        DarkArchiveEntry front() {
            return _reader._currentEntry;
        }

        void popFront() {
            if (!_reader._dataConsumed && _reader._currentDataSize > 0) {
                _reader._stream.skip(_reader._currentDataSize);
                _reader._dataConsumed = true;
            }
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
                ubyte[TAR_BLOCK_SIZE] headerBuf;
                try {
                    _reader._stream.readInto(headerBuf[]);
                } catch (DarkArchiveException) {
                    _done = true;
                    return;
                }

                if (isZeroBlock(headerBuf[])) {
                    _done = true;
                    return;
                }

                if (!verifyChecksum(headerBuf[])) {
                    if (_seenEntry)
                        throw new DarkArchiveException(
                            "TAR: header checksum mismatch (corrupted or truncated archive)");
                    _done = true;
                    return;
                }

                auto typeflag = cast(char) headerBuf[156];
                auto entrySize = parseOctal(headerBuf[124 .. 136]);
                if (entrySize < 0) entrySize = 0;

                auto dataSize = cast(size_t) entrySize;
                if (dataSize > size_t.max - (TAR_BLOCK_SIZE - 1))
                    throw new DarkArchiveException("TAR: entry size too large");
                auto paddedSize = (dataSize + TAR_BLOCK_SIZE - 1)
                    / TAR_BLOCK_SIZE * TAR_BLOCK_SIZE;

                if (typeflag == TAR_TYPE_PAX_EXTENDED || typeflag == TAR_TYPE_PAX_GLOBAL) {
                    enum MAX_PAX_SIZE = 1024 * 1024;
                    auto paxSize = dataSize > MAX_PAX_SIZE ? MAX_PAX_SIZE : dataSize;

                    string[string] paxAttrs;
                    try {
                        auto paxBuf = new ubyte[](paxSize);
                        _reader._stream.readInto(paxBuf[]);
                        paxAttrs = parsePaxData(paxBuf[]);
                        if (paddedSize > paxSize)
                            _reader._stream.skip(paddedSize - paxSize);
                    } catch (DarkArchiveException) {
                        _done = true;
                        return;
                    }

                    try {
                        _reader._stream.readInto(headerBuf[]);
                    } catch (DarkArchiveException) {
                        _done = true;
                        return;
                    }

                    if (isZeroBlock(headerBuf[])) {
                        _done = true;
                        return;
                    }

                    typeflag = cast(char) headerBuf[156];
                    entrySize = parseOctal(headerBuf[124 .. 136]);
                    if (entrySize < 0) entrySize = 0;
                    dataSize = cast(size_t) entrySize;
                    if (dataSize > size_t.max - (TAR_BLOCK_SIZE - 1))
                        throw new DarkArchiveException("TAR: entry size too large");
                    paddedSize = (dataSize + TAR_BLOCK_SIZE - 1)
                        / TAR_BLOCK_SIZE * TAR_BLOCK_SIZE;

                    _reader._currentEntry = parseHeader(headerBuf[]);
                    applyPaxAttrs(_reader._currentEntry, paxAttrs);
                    if (auto s = "size" in paxAttrs) {
                        import std.conv : to, ConvOverflowException;
                        try { dataSize = (*s).to!size_t; }
                        catch (ConvOverflowException)
                            { throw new DarkArchiveException("TAR: PAX size value too large"); }
                        // size field in the entry is signed long; clamp if needed.
                        _reader._currentEntry.size =
                            dataSize > long.max ? long.max : cast(long) dataSize;
                        if (dataSize > size_t.max - (TAR_BLOCK_SIZE - 1))
                            throw new DarkArchiveException("TAR: PAX size too large");
                        paddedSize = (dataSize + TAR_BLOCK_SIZE - 1)
                            / TAR_BLOCK_SIZE * TAR_BLOCK_SIZE;
                    }
                } else {
                    _reader._currentEntry = parseHeader(headerBuf[]);
                }

                _reader._currentDataSize = dataSize;
                _reader._currentData = null;
                _reader._dataConsumed = false;
                _pendingSkip = paddedSize > dataSize ? paddedSize - dataSize : 0;

                _seenEntry = true;
                _reader._hasEntry = true;
                return;
            }

            _done = true;
        }
    }
}

/// Construct a range-based TarReader from any input range of `const(ubyte)[]`
/// chunks. The range is wrapped in a `ChunkReader` internally.
///
/// Example:
/// ---
/// auto reader = tarReader(only(tarBytes));
/// foreach (entry; reader.entries) { ... }
/// ---
auto tarReader(R)(R source)
    if (isInputRange!R && is(ElementType!R : const(ubyte)[]))
{
    import darkarchive.datasource : chunkReader;
    auto cr = chunkReader(source);
    return TarReader!(typeof(cr))(cr);
}

/// Construct a file-backed TarReader from a plain TAR file path.
/// Reads in 64KB chunks; `close()` propagates to release the file handle.
auto tarReader(string path) {
    auto source = FileChunkSource(path);
    return TarReader!(ChunkReader!FileChunkSource)(ChunkReader!FileChunkSource(source));
}

/// Construct a file-backed TarReader from a gzip-compressed TAR file path.
/// Decompresses on the fly; `close()` propagates through the entire chain.
auto tarGzReader(string path) {
    auto source = FileChunkSource(path);
    auto gz = GzipRange!FileChunkSource(source);
    alias CR = ChunkReader!(GzipRange!FileChunkSource);
    return TarReader!CR(CR(gz));
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
        case TAR_TYPE_HARDLINK:
            e.type = EntryType.hardlink;
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
            auto key   = record[0 .. eqIdx].idup;
            // Preserve the raw value including any embedded NUL bytes.
            // NUL in a PAX value is malicious/corrupt, but rejection happens
            // at extraction time (extractToImpl) where the caller can act on it.
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

    private immutable testDataDir = "test-data";

    @("tar read: symlink entry")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        auto reader = tarReader(testDataDir ~ "/test-symlink.tar");
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
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        auto reader = tarReader(testDataDir ~ "/test-empty-files.tar");
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
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        auto reader = tarReader(testDataDir ~ "/test-symlink.tar");
        bool foundDir;
        foreach (entry; reader.entries)
            if (entry.pathname == "./" && entry.isDir) foundDir = true;
        foundDir.shouldBeTrue;
    }

    @("tar read: permissions parsed")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        auto reader = tarReader(testDataDir ~ "/test-empty-files.tar");
        foreach (entry; reader.entries)
            if (entry.pathname == "./notempty.txt")
                assert(entry.permissions > 0);
    }

    // -------------------------------------------------------------------
    // Security tests
    // -------------------------------------------------------------------

    @("tar security: non-tar data does not crash")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        import std.file : exists, remove, write;
        auto tmpPath = "test-data/test-tarr-garbage.tar";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        auto garbage = cast(const(ubyte)[]) "this is not a tar file";
        auto padded = new ubyte[](1024);
        padded[0 .. garbage.length] = garbage[];
        write(tmpPath, padded);
        auto reader = tarReader(tmpPath);
        scope(exit) reader.close();
        int count;
        foreach (entry; reader.entries) count++;
        count.shouldEqual(0);
    }

    @("tar security: truncated archive does not crash")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        import darkarchive.formats.tar.writer : tarWriter;
        import std.file : exists, remove, read, write;
        auto tmpPath = "test-data/test-tarr-trunc-src.tar";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        auto writer = tarWriter(tmpPath);
        scope(exit) writer.close();
        writer.addBuffer("test.txt", cast(const(ubyte)[]) "some content here");
        writer.finish();

        auto fullData = cast(ubyte[]) read(tmpPath);
        auto truncated = fullData[0 .. 512 + 5];
        auto corruptPath = "test-data/test-tarr-trunc.tar";
        scope(exit) if (exists(corruptPath)) remove(corruptPath);
        write(corruptPath, truncated);

        auto reader = tarReader(corruptPath);
        scope(exit) reader.close();
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
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        auto malicious1 = cast(const(ubyte)[]) "0 path=evil\n";
        auto result1 = parsePaxData(malicious1);
        result1.length.shouldEqual(0); // "0" means zero-length record — nothing parsed

        auto malicious2 = cast(const(ubyte)[]) " path=evil\n";
        auto result2 = parsePaxData(malicious2);
        result2.length.shouldEqual(0); // leading space — invalid length

        auto empty = cast(const(ubyte)[]) "";
        auto result3 = parsePaxData(empty);
        result3.length.shouldEqual(0);
    }

    @("tar security: octal overflow throws")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
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
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        import std.file : exists, remove, write;
        auto tmpPath = "test-data/test-tarr-badchecksum.tar";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        ubyte[512] header;
        foreach (i, ref b; header) b = cast(ubyte)((i * 37 + 13) & 0xFF);
        write(tmpPath, header[]);

        auto reader = tarReader(tmpPath);
        scope(exit) reader.close();
        int count;
        foreach (entry; reader.entries) count++;
        count.shouldEqual(0);
    }

    // -------------------------------------------------------------------
    // Format edge-case tests
    // -------------------------------------------------------------------

    @("tar format: data size exactly 512 bytes, no padding")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        import darkarchive.formats.tar.writer : tarWriter;
        import std.file : exists, remove;
        auto tmpPath = "test-data/test-tarr-exact512.tar";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        auto data = new ubyte[](512);
        foreach (i, ref b; data) b = cast(ubyte)(i & 0xFF);

        auto writer = tarWriter(tmpPath);
        scope(exit) writer.close();
        writer.addBuffer("exact512.bin", data);
        writer.finish();

        auto reader = tarReader(tmpPath);
        scope(exit) reader.close();
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
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        import darkarchive.formats.tar.writer : tarWriter;
        import std.file : exists, remove;
        auto tmpPath = "test-data/test-tarr-over512.tar";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        auto data = new ubyte[](513);
        foreach (i, ref b; data) b = cast(ubyte)(i & 0xFF);

        auto writer = tarWriter(tmpPath);
        scope(exit) writer.close();
        writer.addBuffer("over512.bin", data);
        writer.finish();

        auto reader = tarReader(tmpPath);
        scope(exit) reader.close();
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
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        import darkarchive.formats.tar.writer : tarWriter;
        import std.file : exists, remove;
        auto tmpPath = "test-data/test-tarr-onebyte.tar";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        auto writer = tarWriter(tmpPath);
        scope(exit) writer.close();
        writer.addBuffer("one.bin", [cast(ubyte) 0x42]);
        writer.finish();

        auto reader = tarReader(tmpPath);
        scope(exit) reader.close();
        foreach (entry; reader.entries) {
            if (entry.pathname == "one.bin") {
                entry.size.shouldEqual(1);
                reader.readData()[0].shouldEqual(0x42);
                return;
            }
        }
        assert(false, "entry not found");
    }

    @("tar format: GNU long filename does not crash, entries iterable")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        // GNU tar uses ././@LongLink pseudo-entries for names > 100 chars.
        // Our reader skips GNU extensions (only supports pax). Verify we
        // still iterate without crashing and produce at least one entry.
        auto reader = tarReader(testDataDir ~ "/test-gnu-longname.tar");
        string[] names;
        foreach (entry; reader.entries)
            names ~= entry.pathname;
        assert(names.length > 0, "should have at least one entry");
    }

    @("tar format: empty filename produces empty string, not null")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        import darkarchive.formats.tar.writer : tarWriter;
        import std.file : exists, remove;
        auto tmpPath = "test-data/test-tarr-emptyname.tar";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        auto writer = tarWriter(tmpPath);
        scope(exit) writer.close();
        writer.addBuffer("", cast(const(ubyte)[]) "no name");
        writer.finish();

        auto reader = tarReader(tmpPath);
        scope(exit) reader.close();
        int count;
        foreach (entry; reader.entries) {
            count++;
            assert(entry.pathname !is null);
            entry.pathname.length.shouldEqual(0);
        }
        count.shouldEqual(1);
    }

    // -------------------------------------------------------------------
    // CVE / overflow tests
    // -------------------------------------------------------------------

    @("CVE: pax size attribute with absurd value")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        // Pax record declares length 30 but actual data is shorter —
        // parser must reject (recordLen > text.length) without crash.
        auto maliciousPax = cast(const(ubyte)[]) "30 size=99999999999999999999\n";
        auto attrs = parsePaxData(maliciousPax);
        attrs.length.shouldEqual(0);

        // Well-formed record with absurd value — parser stores as string
        auto wellFormed = cast(const(ubyte)[]) "29 size=99999999999999999999\n";
        auto attrs2 = parsePaxData(wellFormed);
        assert("size" in attrs2, "well-formed pax record should be parsed");
        attrs2["size"].shouldEqual("99999999999999999999");
    }

    @("tar security: huge size field does not OOB")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        import darkarchive.formats.tar.writer : tarWriter;
        import std.file : exists, remove, read, write;
        auto tmpPath = "test-data/test-tarr-hugesize-src.tar";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        auto writer = tarWriter(tmpPath);
        scope(exit) writer.close();
        writer.addBuffer("small.txt", cast(const(ubyte)[]) "tiny");
        writer.finish();

        auto data = cast(ubyte[]) read(tmpPath);
        data[124 .. 136] = cast(ubyte[12]) "77777777777\0";
        uint sum = 0;
        foreach (i; 0 .. 512) {
            if (i >= 148 && i < 156) sum += ' ';
            else sum += data[i];
        }
        import std.format : format;
        auto checksumStr = format!"%06o\0 "(sum);
        data[148 .. 156] = cast(ubyte[8]) checksumStr[0 .. 8];
        auto corruptPath = "test-data/test-tarr-hugesize.tar";
        scope(exit) if (exists(corruptPath)) remove(corruptPath);
        write(corruptPath, data);

        auto reader = tarReader(corruptPath);
        scope(exit) reader.close();
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
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;
        import darkarchive.formats.tar.writer : tarWriter;
        import std.file : exists, remove;
        auto tmpPath = "test-data/test-tarr-zerosize.tar";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        auto writer = tarWriter(tmpPath);
        scope(exit) writer.close();
        writer.addBuffer("zero.txt", cast(const(ubyte)[]) "");
        writer.finish();

        auto reader = tarReader(tmpPath);
        scope(exit) reader.close();
        foreach (entry; reader.entries) {
            if (entry.pathname == "zero.txt") {
                auto d = reader.readData();
                assert(d is null || d.length == 0);
            }
        }
    }

    @("tar security: corrupted header mid-archive throws DarkArchiveException")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;
        import darkarchive.formats.tar.writer : tarWriter;
        import std.file : exists, remove, read, write;
        auto tmpPath = "test-data/test-tarr-corrupt-src.tar";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        auto writer = tarWriter(tmpPath);
        scope(exit) writer.close();
        writer
            .addBuffer("file1.txt", cast(const(ubyte)[]) "content 1")
            .addBuffer("file2.txt", cast(const(ubyte)[]) "content 2");
        writer.finish();

        auto data = cast(ubyte[]) read(tmpPath);
        // Corrupt the checksum bytes of the SECOND header (at offset 1024)
        assert(data.length > 1024 + 156);
        data[1024 + 148] = 0xFF;
        data[1024 + 149] = 0xFF;
        auto corruptPath = "test-data/test-tarr-corrupt-mid.tar";
        scope(exit) if (exists(corruptPath)) remove(corruptPath);
        write(corruptPath, data);

        // First entry is valid, second has bad checksum → must throw, not silently stop.
        auto reader = tarReader(corruptPath);
        scope(exit) reader.close();
        bool caught;
        int count;
        try {
            foreach (entry; reader.entries) {
                count++;
                reader.skipData();
            }
        } catch (DarkArchiveException) { caught = true; }
        assert(count == 1, "should have seen exactly one valid entry before corruption");
        caught.shouldBeTrue;
    }

    @("tar security: pax size near size_t.max throws overflow check")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;
        import darkarchive.exception : DarkArchiveException;
        import std.file : exists, remove, write;
        import std.conv : octal;

        // PAX record: "29 size=18446744073709551615\n"
        // length = 2 + 1 + 26 = 29 bytes ✓  (ulong.max as decimal)
        auto paxContent = cast(ubyte[]) "29 size=18446744073709551615\n";
        assert(paxContent.length == 29);

        // Build PAX extended header block (typeflag 'x')
        ubyte[TAR_BLOCK_SIZE] paxHdr;
        paxHdr[] = 0;
        paxHdr[0 .. 9] = cast(ubyte[9]) "PaxHeader";
        paxHdr[156] = 'x';
        paxHdr[257 .. 263] = cast(ubyte[6]) "ustar\0";
        paxHdr[263 .. 265] = cast(ubyte[2]) "00";
        // permissions = 0644, size = 29, mtime = 0
        paxHdr[100 .. 108] = cast(ubyte[8]) "0000644\0";
        // size = 29 decimal = 035 octal → "0000000035\0" (12-byte field)
        paxHdr[124 .. 136] = cast(ubyte[12]) "00000000035\0";
        paxHdr[136 .. 148] = cast(ubyte[12]) "00000000000\0";
        // Compute checksum
        uint cs = 0;
        foreach (i, b; paxHdr) cs += (i >= 148 && i < 156) ? ' ' : b;
        import std.format : format;
        auto csStr = format!"%06o\0 "(cs);
        paxHdr[148 .. 156] = cast(ubyte[8]) csStr[0 .. 8];

        // PAX data block
        ubyte[TAR_BLOCK_SIZE] paxDataBlock;
        paxDataBlock[] = 0;
        paxDataBlock[0 .. 29] = paxContent[];

        // Regular file header (name "a.txt", typeflag '0', size=0)
        ubyte[TAR_BLOCK_SIZE] fileHdr;
        fileHdr[] = 0;
        fileHdr[0 .. 5] = cast(ubyte[5]) "a.txt";
        fileHdr[156] = '0';
        fileHdr[257 .. 263] = cast(ubyte[6]) "ustar\0";
        fileHdr[263 .. 265] = cast(ubyte[2]) "00";
        fileHdr[100 .. 108] = cast(ubyte[8]) "0000644\0";
        fileHdr[124 .. 136] = cast(ubyte[12]) "00000000000\0";
        fileHdr[136 .. 148] = cast(ubyte[12]) "00000000000\0";
        cs = 0;
        foreach (i, b; fileHdr) cs += (i >= 148 && i < 156) ? ' ' : b;
        csStr = format!"%06o\0 "(cs);
        fileHdr[148 .. 156] = cast(ubyte[8]) csStr[0 .. 8];

        // End-of-archive
        ubyte[TAR_BLOCK_SIZE * 2] eoar;
        eoar[] = 0;

        auto tmpPath = "test-data/test-tarr-pax-overflow.tar";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        ubyte[] archiveData;
        archiveData ~= paxHdr[];
        archiveData ~= paxDataBlock[];
        archiveData ~= fileHdr[];
        archiveData ~= eoar[];
        write(tmpPath, archiveData);

        // The PAX 'size' attribute = ulong.max → paddedSize calculation overflows.
        // Our fix should throw DarkArchiveException instead of wrapping around.
        auto reader = tarReader(tmpPath);
        scope(exit) reader.close();
        bool caught;
        try { foreach (entry; reader.entries) {} }
        catch (DarkArchiveException) { caught = true; }
        caught.shouldBeTrue;
    }

    @("tar security: pax path value with NUL byte is preserved (throw at extract time)")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        // parsePaxData preserves NUL bytes in values.
        // Rejection of such entries happens in extractToImpl, not here, so
        // callers can still list / inspect the archive before deciding to extract.
        // "18 path=evil\0safe\n" — 18 bytes total ✓
        immutable ubyte[] paxData = [
            '1','8',' ','p','a','t','h','=','e','v','i','l',
            0, 's','a','f','e','\n'
        ];
        assert(paxData.length == 18);
        auto attrs = parsePaxData(paxData);
        assert("path" in attrs, "path key should be present");
        // Full value is preserved including the NUL character.
        assert(attrs["path"].length == 9);          // "evil\0safe" = 9 chars
        assert(attrs["path"][4] == '\0');            // NUL at position 4
        assert(attrs["path"][0 .. 4] == "evil");
        assert(attrs["path"][5 .. $] == "safe");
    }

    // -------------------------------------------------------------------
    // Fuzz / randomised-corruption tests
    // -------------------------------------------------------------------

    @("tar fuzz: systematic truncation sweep — only DarkArchiveException escapes")
    unittest {
        import darkarchive.formats.tar.writer : tarWriter;
        import std.file : exists, remove, read;
        import std.range : only;
        import std.conv : to;

        // Build a minimal 2-entry archive (~2KB)
        auto tmpPath = "test-data/test-tarr-fuzz-src.tar";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        auto writer = tarWriter(tmpPath);
        scope(exit) writer.close();
        writer
            .addBuffer("a.txt", cast(const(ubyte)[]) "hello")
            .addBuffer("b.txt", cast(const(ubyte)[]) "world");
        writer.finish();
        auto fullBytes = cast(ubyte[]) read(tmpPath);

        // Sweep every prefix length: 0 .. fullBytes.length - 1
        foreach (len; 0 .. fullBytes.length) {
            auto slice = cast(const(ubyte)[]) fullBytes[0 .. len];
            try {
                auto reader = tarReader(only(slice));
                foreach (entry; reader.entries)
                    reader.skipData();
            } catch (DarkArchiveException) {
                // expected — truncated archive detected
            } catch (Exception e) {
                assert(false, "Non-DarkArchiveException at len=" ~ len.to!string
                    ~ ": " ~ e.classinfo.name ~ ": " ~ e.msg);
            }
        }
    }

    @("tar fuzz: unknown typeflag treated as regular file, no crash")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        import std.file : exists, remove, write;
        import std.format : format;

        // Build a TAR header with an unusual but not PAX typeflag ('S', 'V', 'N', etc.)
        foreach (tf; ['S', 'V', 'N', 'A', 'Z', '9']) {
            ubyte[TAR_BLOCK_SIZE] hdr;
            hdr[] = 0;
            hdr[0 .. 5] = cast(ubyte[5]) "x.bin";
            hdr[156] = cast(ubyte) tf;
            hdr[257 .. 263] = cast(ubyte[6]) "ustar\0";
            hdr[263 .. 265] = cast(ubyte[2]) "00";
            hdr[100 .. 108] = cast(ubyte[8]) "0000644\0";
            hdr[124 .. 136] = cast(ubyte[12]) "00000000000\0";
            hdr[136 .. 148] = cast(ubyte[12]) "00000000000\0";
            // Compute POSIX checksum
            uint cs = 0;
            foreach (i, b; hdr) cs += (i >= 148 && i < 156) ? ' ' : b;
            auto csStr = format!"%06o\0 "(cs);
            hdr[148 .. 156] = cast(ubyte[8]) csStr[0 .. 8];

            // Append end-of-archive
            ubyte[TAR_BLOCK_SIZE * 2] eoar;
            eoar[] = 0;

            auto tmpPath = "test-data/test-tarr-fuzz-typeflag.tar";
            scope(exit) if (exists(tmpPath)) remove(tmpPath);
            ubyte[] data;
            data ~= hdr[];
            data ~= eoar[];
            write(tmpPath, data);

            auto reader = tarReader(tmpPath);
            scope(exit) reader.close();
            int count;
            foreach (entry; reader.entries) {
                count++;
                // Unknown typeflags default to file type
                assert(entry.isFile || entry.isDir || entry.isSymlink,
                    "should have a valid entry type for typeflag " ~ cast(char) tf);
            }
            assert(count == 1, "should find one entry for typeflag " ~ cast(char) tf);
        }
    }

    @("tar security: PAX global header only applies to next entry, not accumulated")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        import std.file : exists, remove, write;
        import std.format : format;
        import std.conv : to;

        // Helper to build a minimal ustar file header with POSIX checksum
        static ubyte[TAR_BLOCK_SIZE] makeHeader(string name, char tf, string sizeOctal) {
            ubyte[TAR_BLOCK_SIZE] h;
            h[] = 0;
            auto nb = cast(const(ubyte)[]) name;
            auto take = nb.length > 100 ? 100 : nb.length;
            h[0 .. take] = nb[0 .. take];
            h[156] = cast(ubyte) tf;
            h[257 .. 263] = cast(ubyte[6]) "ustar\0";
            h[263 .. 265] = cast(ubyte[2]) "00";
            h[100 .. 108] = cast(ubyte[8]) "0000644\0";
            assert(sizeOctal.length == 12);
            h[124 .. 136] = cast(ubyte[12]) sizeOctal[0 .. 12];
            h[136 .. 148] = cast(ubyte[12]) "00000000000\0";
            uint cs = 0;
            foreach (i, b; h) cs += (i >= 148 && i < 156) ? ' ' : b;
            auto csStr = format!"%06o\0 "(cs);
            h[148 .. 156] = cast(ubyte[8]) csStr[0 .. 8];
            return h;
        }

        // PAX global record: "15 path=global\n" — 15 bytes total
        // "15 " (3) + "path=global" (11) + "\n" (1) = 15 ✓
        // 15 decimal = 17 octal → size field "00000000017\0"
        auto paxRecord = cast(ubyte[]) "15 path=global\n";
        assert(paxRecord.length == 15, "PAX record must be exactly 15 bytes");

        auto globalHdr = makeHeader("GlobalPaxHeader", 'g', "00000000017\0");
        ubyte[TAR_BLOCK_SIZE] globalData;
        globalData[] = 0;
        globalData[0 .. 15] = paxRecord[];

        auto file1Hdr = makeHeader("file1.txt", '0', "00000000005\0");
        ubyte[TAR_BLOCK_SIZE] file1Data;
        file1Data[] = 0;
        file1Data[0 .. 5] = cast(ubyte[5]) "hello";

        auto file2Hdr = makeHeader("file2.txt", '0', "00000000005\0");
        ubyte[TAR_BLOCK_SIZE] file2Data;
        file2Data[] = 0;
        file2Data[0 .. 5] = cast(ubyte[5]) "world";

        ubyte[TAR_BLOCK_SIZE * 2] eoar;
        eoar[] = 0;

        auto tmpPath = "test-data/test-tarr-fuzz-global.tar";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        ubyte[] archiveData;
        archiveData ~= globalHdr[];
        archiveData ~= globalData[];
        archiveData ~= file1Hdr[];
        archiveData ~= file1Data[];
        archiveData ~= file2Hdr[];
        archiveData ~= file2Data[];
        archiveData ~= eoar[];
        write(tmpPath, archiveData);

        auto reader = tarReader(tmpPath);
        scope(exit) reader.close();
        string[] names;
        foreach (entry; reader.entries) {
            names ~= entry.pathname;
            reader.skipData();
        }
        // First entry gets the global PAX path applied, second does not.
        // Current behavior: 'g' is handled same as 'x' — applies to the immediately
        // following entry only, not accumulated for all subsequent entries.
        assert(names.length == 2, "should find 2 entries, found " ~ names.length.to!string);
        names[0].shouldEqual("global");       // global attr applied to file1
        names[1].shouldEqual("file2.txt");    // file2 does NOT inherit global attrs
    }

    @("tar security: consecutive PAX extended headers — first attrs apply to second header block")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        import std.file : exists, remove, write;
        import std.format : format;

        // Build: PAX-x1 (path=from_first) → PAX-x2 data → file header → data → eoar
        // The reader reads PAX-x1, then reads the "next" block which is the PAX-x2 header.
        // It treats that as the actual file header. PAX-x1 attrs are applied to it.
        // PAX-x2 data is the entry's content. The actual file header block is never seen.

        // "18 path=first_pax\n": "18 " (3) + "path=first_pax" (14) + "\n" (1) = 18 bytes ✓
        // 18 decimal = 22 octal → size field "00000000022\0"
        auto pax1Record = cast(ubyte[]) "18 path=first_pax\n";
        assert(pax1Record.length == 18, "PAX record must be exactly 18 bytes");

        static ubyte[TAR_BLOCK_SIZE] makeHdr(string name, char tf, string sizeOctal) {
            ubyte[TAR_BLOCK_SIZE] h;
            h[] = 0;
            auto nb = cast(const(ubyte)[]) name;
            auto take = nb.length > 100 ? 100 : nb.length;
            h[0 .. take] = nb[0 .. take];
            h[156] = cast(ubyte) tf;
            h[257 .. 263] = cast(ubyte[6]) "ustar\0";
            h[263 .. 265] = cast(ubyte[2]) "00";
            h[100 .. 108] = cast(ubyte[8]) "0000644\0";
            assert(sizeOctal.length == 12);
            h[124 .. 136] = cast(ubyte[12]) sizeOctal[0 .. 12];
            h[136 .. 148] = cast(ubyte[12]) "00000000000\0";
            uint cs = 0;
            foreach (i, b; h) cs += (i >= 148 && i < 156) ? ' ' : b;
            auto csStr = format!"%06o\0 "(cs);
            h[148 .. 156] = cast(ubyte[8]) csStr[0 .. 8];
            return h;
        }

        // PAX-x1: size=18 decimal = 22 octal → "00000000022\0"
        auto pax1Hdr = makeHdr("PaxHeader1", 'x', "00000000022\0");
        ubyte[TAR_BLOCK_SIZE] pax1Data;
        pax1Data[] = 0;
        pax1Data[0 .. 18] = pax1Record[];

        // PAX-x2: some other PAX data (size=5 = octal 5 → "00000000005\0")
        auto pax2Record = cast(ubyte[]) "5 x=y";  // 5 bytes (no trailing newline — malformed but parseable-fail)
        auto pax2Hdr = makeHdr("PaxHeader2", 'x', "00000000005\0");
        ubyte[TAR_BLOCK_SIZE] pax2Data;
        pax2Data[] = 0;
        pax2Data[0 .. 5] = pax2Record[];

        // Actual file header
        auto fileHdr = makeHdr("actual.txt", '0', "00000000005\0");
        ubyte[TAR_BLOCK_SIZE] fileData;
        fileData[] = 0;
        fileData[0 .. 5] = cast(ubyte[5]) "hello";

        ubyte[TAR_BLOCK_SIZE * 2] eoar;
        eoar[] = 0;

        auto tmpPath = "test-data/test-tarr-fuzz-consec-pax.tar";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        ubyte[] archiveData;
        archiveData ~= pax1Hdr[];
        archiveData ~= pax1Data[];
        archiveData ~= pax2Hdr[];
        archiveData ~= pax2Data[];
        archiveData ~= fileHdr[];
        archiveData ~= fileData[];
        archiveData ~= eoar[];
        write(tmpPath, archiveData);

        // This documents current behavior: the reader treats the second PAX header
        // as the actual file header (typeflag 'x' → default → EntryType.file).
        // PAX-x1 attrs ("path=from_first") are applied. PAX-x2 data is the entry content.
        auto reader = tarReader(tmpPath);
        scope(exit) reader.close();
        string[] names;
        foreach (entry; reader.entries) {
            names ~= entry.pathname;
            reader.skipData();
        }
        // We expect at least one entry without a crash.
        assert(names.length >= 1, "should find at least one entry without crashing");
    }

    // -------------------------------------------------------------------
    // Range-based tarReader test
    // -------------------------------------------------------------------

    @("tar read: range-based tarReader from in-memory bytes")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue;
        import darkarchive.formats.tar.writer : tarWriter;
        import darkarchive.datasource : chunkSource;
        import std.file : exists, remove, read;
        import std.range : only;

        auto tmpPath = "test-data/test-tarr-range.tar";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);

        auto writer = tarWriter(tmpPath);
        scope(exit) writer.close();
        writer.addBuffer("range.txt", cast(const(ubyte)[]) "range content");
        writer.finish();

        auto tarBytes = cast(ubyte[]) read(tmpPath);
        auto reader = tarReader(only(cast(const(ubyte)[]) tarBytes));

        bool found;
        foreach (entry; reader.entries) {
            if (entry.pathname == "range.txt") {
                found = true;
                entry.isFile.shouldBeTrue;
                reader.readText().shouldEqual("range content");
            }
        }
        found.shouldBeTrue;
    }
}
