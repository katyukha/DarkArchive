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
        File* _file;
        ulong _fileSize;
    }

    /// Create from file path (does not load file into memory).
    static DataSource fromFile(string path) {
        DataSource ds;
        ds._file = new File(path, "rb");
        ds._file.seek(0, SEEK_END);
        ds._fileSize = ds._file.tell();
        return ds;
    }

    /// Close the underlying file handle (if file-backed). Safe to call
    /// multiple times or on memory-backed sources (no-op).
    void close() {
        if (_file !is null) {
            _file.close();
            _file = null;
        }
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
        z_stream _zs;
        bool _zsInit;
        ubyte[] _outBuf;
        const(ubyte)[] _current; // decompressed chunk returned by front()
        bool _done;

        enum OUT_CHUNK = 64 * 1024;
    }

    @disable this();
    @disable this(this); // z_stream holds a state pointer — copying would alias it

    this(R source) {
        _source = source;
        _outBuf = new ubyte[](OUT_CHUNK);
        _zs = z_stream.init;
        if (inflateInit2(&_zs, 15 + 16) != Z_OK)
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
    /// safe to call manually for early termination.
    void close() {
        if (_zsInit) {
            inflateEnd(&_zs);
            _zsInit = false;
        }
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

            auto ret = inflate(&_zs, Z_NO_FLUSH);
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

/// Sequential byte stream — used by TarReader for both plain TAR (backed by
/// DataSource) and TAR.GZ (backed by streaming gzip decompressor).
/// Unlike DataSource, this is a class for polymorphic dispatch.
class SequentialReader {
    /// Read exactly `len` bytes at the current position. Advances position.
    /// Allocates a new buffer each call — prefer readInto for hot paths.
    ubyte[] read(size_t len) {
        assert(false, "not implemented");
    }

    /// Read into a caller-provided buffer. Returns bytes actually read.
    /// Zero-allocation on the hot path — use in readDataChunked.
    size_t readInto(ubyte[] buf) {
        // Default implementation: delegate to read() + copy.
        // Subclasses override for zero-copy.
        auto data = read(buf.length);
        buf[0 .. data.length] = data[];
        return data.length;
    }

    /// Skip `len` bytes (advance position without reading).
    void skip(size_t len) {
        assert(false, "not implemented");
    }

    /// Whether there are more bytes to read.
    bool empty() {
        assert(false, "not implemented");
        return true;
    }

    /// Close underlying resources.
    void close() {}
}

/// SequentialReader backed by a DataSource (memory or file).
class DataSourceSequentialReader : SequentialReader {
    private DataSource* _ds;
    private ulong _pos;

    this(DataSource* ds) {
        _ds = ds;
        _pos = 0;
    }

    override ubyte[] read(size_t len) {
        if (_pos + len > _ds.length)
            throw new DarkArchiveException("TAR: unexpected end of data");
        auto result = cast(ubyte[]) _ds.readSlice(_pos, len).dup;
        _pos += len;
        return result;
    }

    override size_t readInto(ubyte[] buf) {
        auto len = buf.length;
        if (_pos + len > _ds.length)
            throw new DarkArchiveException("TAR: unexpected end of data");
        auto slice = _ds.readSlice(_pos, len);
        buf[0 .. len] = slice[0 .. len];
        _pos += len;
        return len;
    }

    override void skip(size_t len) {
        _pos += len;
        if (_pos > _ds.length)
            _pos = cast(size_t) _ds.length;
    }

    override bool empty() {
        return _pos >= _ds.length;
    }

    override void close() {
        if (_ds !is null)
            _ds.close();
    }
}

/// SequentialReader that pulls bytes from a caller-provided delegate.
///
/// The delegate must return the next chunk of raw bytes on each call,
/// or an empty slice to signal EOF. The returned slice must remain valid
/// until the next call to the delegate — callers are responsible for
/// `.dup`-ing if the source buffer is reused between calls.
class DelegateSequentialReader : SequentialReader {
    private {
        ubyte[] delegate() _source;
        ubyte[] _pending; // unconsumed tail of the last returned chunk
        bool _eof;
    }

    this(ubyte[] delegate() source) {
        _source = source;
    }

    override ubyte[] read(size_t len) {
        auto buf = new ubyte[](len);
        readInto(buf);
        return buf;
    }

    override size_t readInto(ubyte[] buf) {
        size_t filled = 0;
        while (filled < buf.length) {
            if (_pending.length == 0) {
                if (_eof)
                    throw new DarkArchiveException("TAR: unexpected end of stream");
                auto chunk = _source();
                if (chunk.length == 0) { _eof = true; break; }
                _pending = chunk;
            }
            auto take = buf.length - filled;
            if (take > _pending.length) take = _pending.length;
            buf[filled .. filled + take] = _pending[0 .. take];
            filled += take;
            _pending = _pending[take .. $];
        }
        if (filled < buf.length)
            throw new DarkArchiveException("TAR: unexpected end of stream");
        return filled;
    }

    override void skip(size_t len) {
        while (len > 0) {
            if (_pending.length == 0) {
                if (_eof) return;
                auto chunk = _source();
                if (chunk.length == 0) { _eof = true; return; }
                _pending = chunk;
            }
            auto take = len > _pending.length ? _pending.length : len;
            _pending = _pending[take .. $];
            len -= take;
        }
    }

    override bool empty() {
        if (_pending.length > 0) return false;
        if (_eof) return true;
        auto chunk = _source();
        if (chunk.length == 0) { _eof = true; return true; }
        _pending = chunk;
        return false;
    }
}

/// SequentialReader backed by streaming gzip decompression of a file or
/// a caller-provided chunk delegate.
///
/// Uses C zlib directly for bounded memory — decompresses into a fixed-size
/// ring buffer, never accumulating more than DECOMP_BUF_SIZE of decompressed
/// data regardless of compression ratio. Peak memory: ~576KB
/// (512KB decomp buffer + 64KB compressed read buffer).
class GzipSequentialReader : SequentialReader {
    private {
        import std.stdio : File;
        import etc.c.zlib;

        // File-backed source (null when using chunk delegate)
        File _file;

        // Delegate-based source (null when using file)
        ubyte[] delegate() _chunkSource;
        ubyte[] _currentChunk; // pinned so zlib next_in ptr stays valid

        z_stream _zs;
        bool _zsInit;

        // Fixed-size decompression buffer (ring-style: compact when half consumed)
        ubyte[] _decompBuf;
        size_t _decompPos;   // read position within _decompBuf
        size_t _decompLen;   // valid bytes in _decompBuf (from start)

        ubyte[] _readBuf;    // reusable compressed read buffer (file mode only)
        bool _fileEOF;
        bool _inflateEOF;

        enum COMP_CHUNK = 64 * 1024;       // 64KB compressed read chunks
        enum DECOMP_BUF_SIZE = 512 * 1024; // 512KB decompressed buffer
        enum COMPACT_THRESHOLD = 256 * 1024; // compact when 256KB consumed
    }

    /// Construct from a gzip file path.
    this(string gzipPath) {
        _file = File(gzipPath, "rb");
        _decompBuf = new ubyte[](DECOMP_BUF_SIZE);
        _readBuf = new ubyte[](COMP_CHUNK);
        _decompPos = 0;
        _decompLen = 0;
        _fileEOF = false;
        _inflateEOF = false;

        // Initialize C zlib for gzip format (windowBits = 15 + 16 for gzip)
        _zs = z_stream.init;
        auto ret = inflateInit2(&_zs, 15 + 16);
        if (ret != Z_OK)
            throw new DarkArchiveException("GZIP: inflateInit2 failed");
        _zsInit = true;
    }

    /// Construct from a chunk-producing delegate.
    ///
    /// The delegate returns the next compressed chunk on each call,
    /// or an empty slice on EOF. The returned slice must remain valid
    /// until the next delegate call — `.dup` if the source reuses buffers.
    this(ubyte[] delegate() chunkSource) {
        _chunkSource = chunkSource;
        _decompBuf = new ubyte[](DECOMP_BUF_SIZE);
        _decompPos = 0;
        _decompLen = 0;
        _fileEOF = false;
        _inflateEOF = false;

        _zs = z_stream.init;
        auto ret = inflateInit2(&_zs, 15 + 16);
        if (ret != Z_OK)
            throw new DarkArchiveException("GZIP: inflateInit2 failed");
        _zsInit = true;
    }

    override ubyte[] read(size_t len) {
        ensureAvailable(len);
        if (available < len)
            throw new DarkArchiveException("GZIP: unexpected end of compressed data");
        auto result = _decompBuf[_decompPos .. _decompPos + len].dup;
        _decompPos += len;
        compact();
        return result;
    }

    override size_t readInto(ubyte[] buf) {
        auto len = buf.length;
        ensureAvailable(len);
        if (available < len)
            throw new DarkArchiveException("GZIP: unexpected end of compressed data");
        buf[0 .. len] = _decompBuf[_decompPos .. _decompPos + len];
        _decompPos += len;
        compact();
        return len;
    }

    override void skip(size_t len) {
        while (len > 0) {
            if (available == 0) {
                if (!decompressMore())
                    return;
                continue;
            }
            auto toSkip = len > available ? available : len;
            _decompPos += toSkip;
            len -= toSkip;
        }
        compact();
    }

    override bool empty() {
        if (available > 0) return false;
        if (_inflateEOF) return true;
        return !decompressMore();
    }

    override void close() {
        if (_zsInit) {
            inflateEnd(&_zs);
            _zsInit = false;
        }
        if (_chunkSource is null)
            _file.close();
        _chunkSource = null;
        _currentChunk = null;
        _decompBuf = null;
        _readBuf = null;
    }

    private @property size_t available() const {
        return _decompLen - _decompPos;
    }

    private void ensureAvailable(size_t needed) {
        while (available < needed) {
            if (!decompressMore())
                return;
        }
    }

    private bool decompressMore() {
        if (_inflateEOF) return false;

        compact();

        // Fill compressed input if zlib needs more
        if (_zs.avail_in == 0 && !_fileEOF) {
            if (_chunkSource !is null) {
                _currentChunk = _chunkSource(); // pin so zlib ptr stays valid
                if (_currentChunk.length == 0) {
                    _fileEOF = true;
                } else {
                    _zs.next_in  = cast(ubyte*) _currentChunk.ptr;
                    _zs.avail_in = cast(uint)   _currentChunk.length;
                }
            } else {
                auto got = _file.rawRead(_readBuf[]);
                if (got.length == 0) {
                    _fileEOF = true;
                } else {
                    _zs.next_in  = cast(ubyte*) got.ptr;
                    _zs.avail_in = cast(uint)   got.length;
                }
            }
        }

        // Decompress into the free space at end of _decompBuf
        auto freeSpace = _decompBuf.length - _decompLen;
        if (freeSpace == 0) return available > 0; // buffer full, need compact

        _zs.next_out = cast(ubyte*) (_decompBuf.ptr + _decompLen);
        _zs.avail_out = cast(uint) freeSpace;

        auto ret = inflate(&_zs, Z_NO_FLUSH);

        auto produced = freeSpace - _zs.avail_out;
        _decompLen += produced;

        if (ret == Z_STREAM_END) {
            _inflateEOF = true;
            return available > 0;
        }
        if (ret != Z_OK && ret != Z_BUF_ERROR)
            throw new DarkArchiveException("GZIP: inflate failed");

        // Stuck: no compressed input left and inflate made no progress.
        // The stream is truncated — further calls will loop forever otherwise.
        if (produced == 0 && _zs.avail_in == 0 && _fileEOF)
            return false;

        return produced > 0 || available > 0;
    }

    /// Compact: shift unconsumed data to front of buffer.
    private void compact() {
        if (_decompPos >= COMPACT_THRESHOLD) {
            auto rem = available;
            if (rem > 0)
                _decompBuf[0 .. rem] = _decompBuf[_decompPos .. _decompLen];
            _decompPos = 0;
            _decompLen = rem;
        }
    }
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

private {
    import std.bitmanip : nativeToLittleEndian;
    import core.stdc.stdio : SEEK_END;
}


// ===========================================================================
// Unit tests
// ===========================================================================

version(unittest) {

    @("datasource: readSlice at offset")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue;
        import std.file : write, remove;
        enum path = "test-data/tmp-datasource-read.bin";
        write(path, "Hello, World!");
        scope(exit) remove(path);
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
        import std.file : write, remove;
        enum path = "test-data/tmp-datasource-readle.bin";
        write(path, cast(const(ubyte)[]) [0x50, 0x4B, 0x03, 0x04, 0x00]);
        scope(exit) remove(path);
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
        import std.file : write, remove;
        import darkarchive.exception : DarkArchiveException;
        enum path = "test-data/tmp-datasource-oob.bin";
        write(path, "short");
        scope(exit) remove(path);
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

        // Decompress via GzipRange — use while loop (foreach copies the struct,
        // which aliases the z_stream.state C pointer → Z_STREAM_ERROR)
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
