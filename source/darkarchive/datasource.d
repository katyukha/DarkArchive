/// Abstraction over data sources — memory buffer or file.
/// Provides uniform read access for format readers without
/// loading entire files into memory.
module darkarchive.datasource;

import darkarchive.exception : DarkArchiveException;
import std.range : isInputRange, ElementType;
import std.array : front, popFront, empty;

/// Read-only data source backed by a file.
struct DataSource {
    private {
        import std.stdio : File;
        File _file;
        ulong _fileSize;
    }

    /// Create from file path (does not load file into memory).
    static DataSource fromFile(string path) {
        DataSource ds;
        ds._file = File(path, "rb");
        ds._file.seek(0, SEEK_END);
        ds._fileSize = ds._file.tell();
        return ds;
    }

    /// Close the underlying file handle. Safe to call multiple times (no-op if
    /// already closed).
    void close() {
        if (_file.isOpen())
            _file.close();
    }

    /// Total size of the data source.
    ulong length() const {
        return _fileSize;
    }

    /// Read a slice of bytes at the given offset.
    const(ubyte)[] readSlice(ulong offset, ulong len) {
        if (offset + len > length)
            throw new DarkArchiveException("DataSource: read past end of data");

        _file.seek(offset);
        auto buf = new ubyte[](cast(size_t) len);
        auto got = _file.rawRead(buf);
        if (got.length != len)
            throw new DarkArchiveException("DataSource: short read from file");
        return got;
    }

    /// Read a little-endian integer at the given offset.
    T readLE(T)(ulong offset) {
        import std.bitmanip : littleEndianToNative;
        enum N = T.sizeof;
        auto bytes = readSlice(offset, N);
        ubyte[N] buf = bytes[0 .. N];
        return littleEndianToNative!T(buf);
    }

    /// Search backward from `startPos` for a 4-byte signature.
    /// Returns offset or -1 if not found.
    long findBackward(uint signature, ulong startPos, ulong maxSearch) {
        import std.bitmanip : littleEndianToNative;

        auto sigBytes = nativeToLittleEndian(signature);
        auto searchStart = startPos >= maxSearch ? startPos - maxSearch : 0;

        // File-backed: read in chunks from end
        enum CHUNK = 4096;
        auto buf = new ubyte[](CHUNK + 4); // overlap for cross-boundary signatures

        for (long pos = cast(long) startPos; pos >= cast(long) searchStart; pos -= CHUNK) {
            auto readStart = pos >= CHUNK ? pos - CHUNK : 0;
            auto readLen = cast(size_t)(pos + 4 - readStart);
            if (readLen > buf.length) readLen = buf.length;

            _file.seek(readStart);
            auto got = _file.rawRead(buf[0 .. readLen]);

            // Search backward in this chunk
            for (long i = cast(long) got.length - 4; i >= 0; i--) {
                if (got[i .. i + 4] == sigBytes) {
                    auto foundOffset = readStart + i;
                    if (foundOffset <= startPos)
                        return cast(long) foundOffset;
                }
            }

            if (readStart == 0) break;
        }
        return -1;
    }

}

/// Create a chunk-producing delegate from an in-memory byte slice.
///
/// Returns a delegate that yields successive `chunkSize`-byte slices of
/// `data` on each call, and an empty slice once exhausted. Each returned
/// slice is `.dup`-ed, satisfying the chunk-delegate contract that the
/// slice must remain valid until the next call.
ubyte[] delegate() chunkSource(ubyte[] data, size_t chunkSize) {
    size_t offset = 0;
    return () {
        if (offset >= data.length) return cast(ubyte[]) [];
        auto end = offset + chunkSize;
        if (end > data.length) end = data.length;
        auto chunk = data[offset .. end].dup;
        offset = end;
        return chunk;
    };
}

// ===========================================================================
// Range-based streaming: ChunkReader and GzipRange
// ===========================================================================

/// Adapts any input range of `const(ubyte)[]` chunks to a byte-stream interface
/// (`readInto` / `skip` / `empty`) needed by TarReader.
///
/// `_pending` is a slice into the range's last `front` — the range's buffer
/// must remain live until `advance()` is called. Ranges that reuse their buffer
/// between `popFront` calls (e.g. `File.byChunk`) should be wrapped with
/// `.map!(c => c.dup)` before passing, or use the `.dup`-ing overload via
/// `chunkReader`.
struct ChunkReader(R)
    if (isInputRange!R && is(ElementType!R : const(ubyte)[]))
{
    import darkarchive.exception : DarkArchiveException;

    private {
        R _source;
        const(ubyte)[] _pending;
        bool _eof;
    }

    this(R source) {
        _source = source;
    }

    /// True when no more bytes are available.
    bool empty() {
        if (_pending.length > 0) return false;
        if (_eof) return true;
        return !refill();
    }

    /// Read exactly `buf.length` bytes into `buf`. Throws on truncation.
    void readInto(ubyte[] buf) {
        size_t filled = 0;
        while (filled < buf.length) {
            if (_pending.length == 0) {
                if (!refill())
                    throw new DarkArchiveException("TAR: unexpected end of stream");
            }
            auto take = buf.length - filled;
            if (take > _pending.length) take = _pending.length;
            buf[filled .. filled + take] = _pending[0 .. take];
            filled += take;
            _pending = _pending[take .. $];
        }
    }

    /// Skip `len` bytes (consume and discard). Silent on truncation — the next
    /// `readInto` will throw.
    void skip(size_t len) {
        while (len > 0) {
            if (_pending.length == 0) {
                if (!refill()) return;
            }
            auto take = len > _pending.length ? _pending.length : len;
            _pending = _pending[take .. $];
            len -= take;
        }
    }

    /// Propagate close to the underlying source if it supports it.
    static if (__traits(hasMember, R, "close"))
        void close() { _source.close(); }

    private bool refill() {
        while (!_source.empty) {
            auto chunk = cast(const(ubyte)[]) _source.front;
            _source.popFront();
            if (chunk.length > 0) {
                _pending = chunk;
                return true;
            }
        }
        _eof = true;
        return false;
    }
}

/// Construct a `ChunkReader` from any input range of chunks, `.dup`-ing each
/// chunk on read so the range may reuse its buffer between iterations.
auto chunkReader(R)(R source)
    if (isInputRange!R && is(ElementType!R : const(ubyte)[]))
{
    import std.algorithm : map;
    static ubyte[] dupChunk(const(ubyte)[] c) { return c.dup; }
    auto mapped = source.map!dupChunk;
    return ChunkReader!(typeof(mapped))(mapped);
}

/// Input range of decompressed chunks, wrapping any compressed input range.
///
/// Each `front()` yields a `const(ubyte)[]` of decompressed bytes. `popFront()`
/// drives the zlib inflate loop until more output is produced or EOF is reached.
/// Peak memory: one output chunk (64KB) + one pinned compressed input chunk.
struct GzipRange(R)
    if (isInputRange!R && is(ElementType!R : const(ubyte)[]))
{
    import darkarchive.exception : DarkArchiveException;
    import etc.c.zlib;

    private {
        R _source;
        const(ubyte)[] _compChunk; // current compressed chunk, kept for zlib ptr validity
        // Heap-allocated so copies share the same z_stream, keeping zlib's
        // state->strm back-pointer stable (same fix as GzipSink).
        z_stream* _zs;
        bool _zsInit;
        ubyte[] _outBuf;
        const(ubyte)[] _current; // decompressed chunk returned by front()
        bool _done;

        enum OUT_CHUNK = 64 * 1024;
    }

    @disable this();

    this(R source) {
        _source = source;
        _outBuf = new ubyte[](OUT_CHUNK);
        _zs = new z_stream;
        *_zs = z_stream.init;
        if (inflateInit2(_zs, 15 + 16) != Z_OK)
            throw new DarkArchiveException("GZIP: inflateInit2 failed");
        _zsInit = true;
        advance(); // prime: load first decompressed chunk
    }

    /// True once all decompressed output has been consumed.
    bool empty() const { return _current.length == 0; }

    /// Current decompressed chunk. Valid until the next `popFront()`.
    const(ubyte)[] front() { return _current; }

    /// Advance to the next decompressed chunk.
    void popFront() {
        advance();
    }

    /// Release zlib resources. Called automatically on Z_STREAM_END or EOF;
    /// safe to call manually for early termination. Propagates to the source.
    void close() {
        if (_zsInit) {
            inflateEnd(_zs);
            _zsInit = false;
        }
        static if (__traits(hasMember, R, "close"))
            _source.close();
    }

    private void advance() {
        _current = null;
        if (_done) return; // stream exhausted — leave _current null (empty)
        while (true) {
            // Refill zlib input from source range if exhausted
            if (_zs.avail_in == 0) {
                if (_source.empty) {
                    // Truncated stream — no Z_STREAM_END received
                    _done = true;
                    close();
                    return;
                }
                _compChunk = cast(const(ubyte)[]) _source.front.dup;
                _source.popFront();
                _zs.next_in  = cast(ubyte*) _compChunk.ptr;
                _zs.avail_in = cast(uint)   _compChunk.length;
            }

            _zs.next_out  = _outBuf.ptr;
            _zs.avail_out = cast(uint) _outBuf.length;

            auto ret = inflate(_zs, Z_NO_FLUSH);
            auto produced = _outBuf.length - _zs.avail_out;

            if (produced > 0) {
                _current = _outBuf[0 .. produced].dup;
                if (ret == Z_STREAM_END) {
                    _done = true;
                    close();
                }
                return; // have a chunk — caller gets it via front()
            }

            if (ret == Z_STREAM_END) {
                _done = true;
                close();
                return;
            }
            if (ret != Z_OK && ret != Z_BUF_ERROR)
                throw new DarkArchiveException("GZIP: inflate failed");

            // Z_BUF_ERROR + no output + no more input → stuck on truncated stream
            if (_zs.avail_in == 0 && _source.empty) {
                _done = true;
                close();
                return;
            }
            // Otherwise: Z_BUF_ERROR with input still available — loop to refill
        }
    }
}

/// Construct a `GzipRange` from any compressed input range (IFTI).
auto gzipRange(R)(R source)
    if (isInputRange!R && is(ElementType!R : const(ubyte)[]))
{
    return GzipRange!R(source);
}

// ===========================================================================
// In-memory input range of byte chunks (for streaming readers in tests)
// ===========================================================================

/// Input range that yields fixed-size `const(ubyte)[]` slices from an in-memory
/// byte buffer. Useful for feeding streaming readers (TarReader, etc.) from
/// in-memory data without writing a temp file.
struct ByteChunks {
    private const(ubyte)[] _data;
    private size_t _chunkSize;

    bool empty() const { return _data.length == 0; }

    const(ubyte)[] front() const {
        auto n = _chunkSize < _data.length ? _chunkSize : _data.length;
        return _data[0 .. n];
    }

    void popFront() {
        auto n = _chunkSize < _data.length ? _chunkSize : _data.length;
        _data = _data[n .. $];
    }
}

/// Create a `ByteChunks` range from an in-memory buffer.
ByteChunks byChunks(const(ubyte)[] data, size_t chunkSize) {
    return ByteChunks(data, chunkSize);
}

// ===========================================================================
// Output-range sinks
// ===========================================================================

/// Output range backed by a binary file.
struct FileSink {
    private {
        import std.stdio : File;
        File _file;
    }

    this(string path) {
        import std.stdio : File;
        _file = File(path, "wb");
    }

    void put(const(ubyte)[] data) { _file.rawWrite(data); }
    void close() { _file.close(); }
}

/// Output range backed by a delegate pair (put + optional close).
///
/// The write delegate is called for each `put()`; the optional close
/// delegate (if non-null) is called by `close()`.
struct DelegateSink {
    private {
        void delegate(const(ubyte)[]) _put;
        void delegate() _close;
    }

    this(void delegate(const(ubyte)[]) put,
         void delegate() close = null) {
        _put = put;
        _close = close;
    }

    void put(const(ubyte)[] data) {
        if (_put !is null) _put(data);
    }

    void close() {
        if (_close !is null) _close();
    }
}

/// Input range that reads a binary file in fixed-size chunks.
///
/// Each `front()` returns a freshly allocated slice — slices remain valid
/// after `popFront()` is called and across copies of this struct.
/// Call `close()` to release the file handle early; it is NOT called
/// automatically on destruction (no destructor in D structs).
struct FileChunkSource {
    private {
        import std.stdio : File;
        File _file;
        ubyte[] _buf;
        ubyte[] _current;
        bool _eof;
        enum CHUNK = 64 * 1024;
    }

    this(string path) {
        _file = File(path, "rb");
        _buf = new ubyte[](CHUNK);
        refill(); // prime first chunk
    }

    bool empty() const { return _current is null; }

    const(ubyte)[] front() const { return _current; }

    void popFront() { refill(); }

    void close() { _file.close(); }

    private void refill() {
        if (_eof) { _current = null; return; }
        auto got = _file.rawRead(_buf[]);
        if (got.length == 0) {
            _eof = true;
            _current = null;
        } else {
            _current = got.dup;
        }
    }
}

private {
    import std.bitmanip : nativeToLittleEndian;
    import core.stdc.stdio : SEEK_END;
}


// ===========================================================================
// Unit tests
// ===========================================================================

version(unittest) import thepath : Path;

version(unittest) {

    @("datasource: readSlice at offset")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue;
        enum path = "test-data/tmp-datasource-read.bin";
        Path(path).writeFile("Hello, World!");
        scope(exit) Path(path).remove();
        auto ds = DataSource.fromFile(path);
        scope(exit) ds.close();
        ds.length.shouldEqual(13);
        auto slice = ds.readSlice(7, 6);
        (cast(string) slice).shouldEqual("World!");
    }

    @("datasource: read ZIP magic bytes")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue;
        auto ds = DataSource.fromFile("test-data/test-zip.zip");
        scope(exit) ds.close();
        assert(ds.length > 0);
        auto sig = ds.readSlice(0, 2);
        sig[0].shouldEqual('P');
        sig[1].shouldEqual('K');
    }

    @("datasource: readLE")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue;
        enum path = "test-data/tmp-datasource-readle.bin";
        Path(path).writeFile(cast(const(ubyte)[]) [0x50, 0x4B, 0x03, 0x04, 0x00]);
        scope(exit) Path(path).remove();
        auto ds = DataSource.fromFile(path);
        scope(exit) ds.close();
        ds.readLE!uint(0).shouldEqual(0x04034b50);
    }

    @("datasource: findBackward finds EOCD signature")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue;
        import darkarchive.formats.zip.types : ZIP_END_OF_CENTRAL_DIR_SIG;
        auto ds = DataSource.fromFile("test-data/test-zip.zip");
        scope(exit) ds.close();
        auto pos = ds.findBackward(ZIP_END_OF_CENTRAL_DIR_SIG,
            ds.length - 4, 22 + 65535);
        assert(pos >= 0, "should find EOCD signature");
    }

    @("datasource: out-of-bounds read throws")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue;
        import darkarchive.exception : DarkArchiveException;
        enum path = "test-data/tmp-datasource-oob.bin";
        Path(path).writeFile("short");
        scope(exit) Path(path).remove();
        auto ds = DataSource.fromFile(path);
        scope(exit) ds.close();
        bool caught;
        try {
            ds.readSlice(0, 100);
        } catch (DarkArchiveException) {
            caught = true;
        }
        caught.shouldBeTrue;
    }

    // -------------------------------------------------------------------
    // FileChunkSource
    // -------------------------------------------------------------------

    @("FileChunkSource: empty file is immediately empty")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;
        enum path = "test-data/tmp-fcs-empty.bin";
        Path(path).writeFile(cast(ubyte[]) []);
        scope(exit) Path(path).remove();
        auto src = FileChunkSource(path);
        scope(exit) src.close();
        src.empty.shouldBeTrue;
    }

    @("FileChunkSource: close propagates through ChunkReader to tarReader")
    unittest {
        // After close(), the file handle must be released so a second open succeeds.
        // On Linux this is always true; the test also verifies the close chain
        // TarReader → ChunkReader → FileChunkSource → File does not throw.
        import darkarchive.formats.tar.reader : tarReader;
        auto reader = tarReader("test-data/test-empty-files.tar");
        reader.close();
        // Re-open same path — would fail on some OS if file handle leaked
        auto reader2 = tarReader("test-data/test-empty-files.tar");
        scope(exit) reader2.close();
        int count;
        foreach (entry; reader2.entries) count++;
        assert(count > 0, "should read entries on second open");
    }

    // -------------------------------------------------------------------
    // ChunkReader
    // -------------------------------------------------------------------

    @("ChunkReader: readInto across multiple chunks")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        // Source: three 4-byte chunks
        const(ubyte)[][] chunks = [
            cast(const(ubyte)[]) "ABCD",
            cast(const(ubyte)[]) "EFGH",
            cast(const(ubyte)[]) "IJKL",
        ];
        auto r = ChunkReader!(const(ubyte)[][])(chunks);
        ubyte[9] buf;
        r.readInto(buf[]);
        (cast(string) buf[]).shouldEqual("ABCDEFGHI");
        // Read remaining 3 bytes
        r.readInto(buf[0 .. 3]);
        (cast(string) buf[0 .. 3]).shouldEqual("JKL");
        r.empty.shouldEqual(true);
    }

    @("ChunkReader: skip across chunks")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        const(ubyte)[][] chunks = [
            cast(const(ubyte)[]) "AAAA",
            cast(const(ubyte)[]) "BBBB",
            cast(const(ubyte)[]) "CCCC",
        ];
        auto r = ChunkReader!(const(ubyte)[][])(chunks);
        r.skip(6); // skip AAAA + BB
        ubyte[6] buf;
        r.readInto(buf[]);
        (cast(string) buf[]).shouldEqual("BBCCCC");
    }

    @("ChunkReader: readInto throws on truncation")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;
        import darkarchive.exception : DarkArchiveException;
        const(ubyte)[][] chunks = [cast(const(ubyte)[]) "AB"];
        auto r = ChunkReader!(const(ubyte)[][])(chunks);
        bool threw;
        try {
            ubyte[10] buf;
            r.readInto(buf[]);
        } catch (DarkArchiveException) {
            threw = true;
        }
        threw.shouldBeTrue;
    }

    @("ChunkReader: empty chunks are skipped transparently")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        const(ubyte)[][] chunks = [
            cast(const(ubyte)[]) "",
            cast(const(ubyte)[]) "Hello",
            cast(const(ubyte)[]) "",
            cast(const(ubyte)[]) " World",
        ];
        auto r = ChunkReader!(const(ubyte)[][])(chunks);
        ubyte[11] buf;
        r.readInto(buf[]);
        (cast(string) buf[]).shouldEqual("Hello World");
    }

    // -------------------------------------------------------------------
    // GzipRange
    // -------------------------------------------------------------------

    @("GzipRange: decompress known gzip stream")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        import std.zlib : Compress, HeaderFormat;
        import std.range : only;

        // Compress known data
        auto c = new Compress(6, HeaderFormat.gzip);
        ubyte[] compressed = cast(ubyte[]) c.compress(cast(ubyte[]) "Hello, GzipRange!");
        compressed ~= cast(ubyte[]) c.flush();

        // Decompress via GzipRange (z_stream is now heap-allocated, copying is safe)
        auto range = only(cast(const(ubyte)[]) compressed);
        auto gz = GzipRange!(typeof(range))(range);
        ubyte[] result;
        while (!gz.empty) { result ~= gz.front; gz.popFront(); }

        (cast(string) result).shouldEqual("Hello, GzipRange!");
    }

    @("GzipRange: works with multiple compressed input chunks")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        import std.zlib : Compress, HeaderFormat;

        auto c = new Compress(6, HeaderFormat.gzip);
        ubyte[] compressed = cast(ubyte[]) c.compress(cast(ubyte[]) "chunked input test");
        compressed ~= cast(ubyte[]) c.flush();

        // Split into small chunks to exercise multi-chunk feeding
        const(ubyte)[][] chunks;
        for (size_t i = 0; i < compressed.length; i += 4)
            chunks ~= cast(const(ubyte)[]) compressed[i .. (i + 4 < compressed.length ? i + 4 : compressed.length)];

        auto gz = GzipRange!(const(ubyte)[][])(chunks);
        ubyte[] result;
        while (!gz.empty) { result ~= gz.front; gz.popFront(); }

        (cast(string) result).shouldEqual("chunked input test");
    }

    @("GzipRange: truncated stream stops iteration without hanging")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;
        import std.zlib : Compress, HeaderFormat;
        import std.range : only;

        auto c = new Compress(6, HeaderFormat.gzip);
        ubyte[] compressed = cast(ubyte[]) c.compress(cast(ubyte[]) "truncation test data");
        compressed ~= cast(ubyte[]) c.flush();

        // Feed only first half — truncated stream
        auto truncated = compressed[0 .. compressed.length / 2].dup;
        auto range = only(cast(const(ubyte)[]) truncated);
        auto gz = GzipRange!(typeof(range))(range);

        // Must iterate to completion without hanging (may produce partial output or none)
        size_t iterations;
        while (!gz.empty) {
            gz.popFront();
            iterations++;
            if (iterations > 1000) assert(false, "GzipRange looped too many times");
        }
        gz.empty.shouldBeTrue;
    }
}
