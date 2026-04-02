/// Abstraction over data sources — memory buffer or file.
/// Provides uniform read access for format readers without
/// loading entire files into memory.
module darkarchive.datasource;

import darkarchive.exception : DarkArchiveException;

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

/// SequentialReader backed by streaming gzip decompression of a file.
/// Uses C zlib directly for bounded memory — decompresses into a fixed-size
/// ring buffer, never accumulating more than DECOMP_BUF_SIZE of decompressed
/// data regardless of compression ratio. Peak memory: ~576KB
/// (512KB decomp buffer + 64KB compressed read buffer).
class GzipSequentialReader : SequentialReader {
    private {
        import std.stdio : File;
        import etc.c.zlib;

        File _file;
        z_stream _zs;
        bool _zsInit;

        // Fixed-size decompression buffer (ring-style: compact when half consumed)
        ubyte[] _decompBuf;
        size_t _decompPos;   // read position within _decompBuf
        size_t _decompLen;   // valid bytes in _decompBuf (from start)

        ubyte[] _readBuf;    // reusable compressed read buffer
        bool _fileEOF;
        bool _inflateEOF;

        enum COMP_CHUNK = 64 * 1024;      // 64KB compressed read chunks
        enum DECOMP_BUF_SIZE = 512 * 1024; // 512KB decompressed buffer
        enum COMPACT_THRESHOLD = 256 * 1024; // compact when 256KB consumed
    }

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
        _file.close();
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
            auto got = _file.rawRead(_readBuf[]);
            if (got.length == 0) {
                _fileEOF = true;
            } else {
                _zs.next_in = cast(ubyte*) got.ptr;
                _zs.avail_in = cast(uint) got.length;
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

private {
    import std.bitmanip : nativeToLittleEndian;
    import core.stdc.stdio : SEEK_END;
}


// ===========================================================================
// Unit tests
// ===========================================================================

version(unittest) {
    import unit_threaded.assertions : shouldEqual, shouldBeTrue;

    @("datasource: readSlice at offset")
    unittest {
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
        auto ds = DataSource.fromFile("test-data/test-zip.zip");
        scope(exit) ds.close();
        assert(ds.length > 0);
        auto sig = ds.readSlice(0, 2);
        sig[0].shouldEqual('P');
        sig[1].shouldEqual('K');
    }

    @("datasource: readLE")
    unittest {
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
        import darkarchive.formats.zip.types : ZIP_END_OF_CENTRAL_DIR_SIG;
        auto ds = DataSource.fromFile("test-data/test-zip.zip");
        scope(exit) ds.close();
        auto pos = ds.findBackward(ZIP_END_OF_CENTRAL_DIR_SIG,
            ds.length - 4, 22 + 65535);
        assert(pos >= 0, "should find EOCD signature");
    }

    @("datasource: out-of-bounds read throws")
    unittest {
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
}
