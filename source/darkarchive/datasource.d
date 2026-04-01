/// Abstraction over data sources — memory buffer or file.
/// Provides uniform read access for format readers without
/// loading entire files into memory.
module darkarchive.datasource;

import darkarchive.exception : DarkArchiveException;

/// Read-only data source. Backed by either a memory buffer or a file.
struct DataSource {
    private {
        // Memory-backed
        const(ubyte)[] _memData;

        // File-backed
        import std.stdio : File;
        File* _file;
        ulong _fileSize;
    }

    /// Create from memory buffer.
    static DataSource fromMemory(const(ubyte)[] data) {
        DataSource ds;
        ds._memData = data;
        return ds;
    }

    /// Create from file path (does not load file into memory).
    static DataSource fromFile(string path) {
        DataSource ds;
        ds._file = new File(path, "rb");
        ds._file.seek(0, SEEK_END);
        ds._fileSize = ds._file.tell();
        return ds;
    }

    /// Total size of the data source.
    ulong length() const {
        if (_file !is null)
            return _fileSize;
        return _memData.length;
    }

    /// Read a slice of bytes at the given offset.
    /// For memory: returns a slice (zero-copy).
    /// For file: reads into a new buffer.
    const(ubyte)[] readSlice(ulong offset, ulong len) {
        if (offset + len > length)
            throw new DarkArchiveException("DataSource: read past end of data");

        if (_file !is null) {
            _file.seek(offset);
            auto buf = new ubyte[](cast(size_t) len);
            auto got = _file.rawRead(buf);
            if (got.length != len)
                throw new DarkArchiveException("DataSource: short read from file");
            return got;
        }

        return _memData[cast(size_t) offset .. cast(size_t)(offset + len)];
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

        if (_file !is null) {
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

        // Memory-backed: simple scan
        for (long i = cast(long) startPos; i >= cast(long) searchStart; i--) {
            if (i + 4 <= _memData.length &&
                _memData[cast(size_t) i .. cast(size_t)(i + 4)] == sigBytes)
                return i;
        }
        return -1;
    }

}

/// Sequential byte stream — used by TarReader for both plain TAR (backed by
/// DataSource) and TAR.GZ (backed by streaming gzip decompressor).
/// Unlike DataSource, this is a class for polymorphic dispatch.
class SequentialReader {
    /// Read exactly `len` bytes at the current position. Advances position.
    /// Returns the bytes, or throws if not enough data.
    ubyte[] read(size_t len) {
        assert(false, "not implemented");
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

    override void skip(size_t len) {
        _pos += len;
        if (_pos > _ds.length)
            _pos = cast(size_t) _ds.length;
    }

    override bool empty() {
        return _pos >= _ds.length;
    }
}

/// SequentialReader backed by streaming gzip decompression of a file.
/// Decompresses on the fly in chunks — never holds the full decompressed
/// data in memory. Peak memory: ~8MB (4MB compressed read buffer + 4MB
/// decompressed output buffer).
class GzipSequentialReader : SequentialReader {
    private {
        import std.stdio : File;
        import std.zlib : UnCompress, HeaderFormat;

        File _file;
        UnCompress _inflater;
        ubyte[] _decompBuf;  // buffered decompressed data
        size_t _decompPos;   // read position within _decompBuf
        bool _fileEOF;
        bool _inflateEOF;
        enum CHUNK_SIZE = 4 * 1024 * 1024; // 4MB compressed read chunks
    }

    this(string gzipPath) {
        _file = File(gzipPath, "rb");
        _inflater = new UnCompress(HeaderFormat.gzip);
        _decompBuf = [];
        _decompPos = 0;
        _fileEOF = false;
        _inflateEOF = false;
    }

    override ubyte[] read(size_t len) {
        ensureAvailable(len);
        if (_decompPos + len > _decompBuf.length)
            throw new DarkArchiveException("GZIP: unexpected end of compressed data");
        auto result = _decompBuf[_decompPos .. _decompPos + len].dup;
        _decompPos += len;
        compactBuffer();
        return result;
    }

    override void skip(size_t len) {
        // For large skips, decompress and discard in chunks
        while (len > 0) {
            auto available = _decompBuf.length - _decompPos;
            if (available == 0) {
                if (!decompressMore())
                    return; // EOF
                continue;
            }
            auto toSkip = len > available ? available : len;
            _decompPos += toSkip;
            len -= toSkip;
            compactBuffer();
        }
    }

    override bool empty() {
        if (_decompPos < _decompBuf.length) return false;
        if (_inflateEOF) return true;
        return !decompressMore();
    }

    private void ensureAvailable(size_t needed) {
        while (_decompBuf.length - _decompPos < needed) {
            if (!decompressMore())
                return; // can't get more
        }
    }

    private bool decompressMore() {
        if (_inflateEOF) return false;

        ubyte[CHUNK_SIZE] readBuf;
        while (true) {
            if (_fileEOF) {
                auto tail = cast(ubyte[]) _inflater.flush();
                if (tail.length > 0) {
                    _decompBuf ~= tail;
                }
                _inflateEOF = true;
                return _decompBuf.length - _decompPos > 0;
            }

            auto got = _file.rawRead(readBuf[]);
            if (got.length == 0) {
                _fileEOF = true;
                continue;
            }

            auto decompressed = cast(ubyte[]) _inflater.uncompress(got);
            if (decompressed.length > 0) {
                _decompBuf ~= decompressed;
                return true;
            }
        }
    }

    private void compactBuffer() {
        // When we've consumed a significant portion, compact to free memory
        if (_decompPos > CHUNK_SIZE) {
            _decompBuf = _decompBuf[_decompPos .. $].dup;
            _decompPos = 0;
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

    @("datasource: memory-backed read")
    unittest {
        auto data = cast(const(ubyte)[]) "Hello, World!";
        auto ds = DataSource.fromMemory(data);
        ds.length.shouldEqual(13);
        auto slice = ds.readSlice(7, 6);
        (cast(string) slice).shouldEqual("World!");
    }

    @("datasource: file-backed read")
    unittest {
        auto ds = DataSource.fromFile("test-data/test-zip.zip");
        assert(ds.length > 0);
        // Read first 2 bytes — should be "PK"
        auto sig = ds.readSlice(0, 2);
        sig[0].shouldEqual('P');
        sig[1].shouldEqual('K');
    }

    @("datasource: readLE")
    unittest {
        auto data = cast(const(ubyte)[]) [0x50, 0x4B, 0x03, 0x04, 0x00];
        auto ds = DataSource.fromMemory(data);
        ds.readLE!uint(0).shouldEqual(0x04034b50);
    }

    @("datasource: findBackward memory")
    unittest {
        import darkarchive.formats.zip.types : ZIP_END_OF_CENTRAL_DIR_SIG;
        import std.file : read;
        auto data = cast(const(ubyte)[]) read("test-data/test-zip.zip");
        auto ds = DataSource.fromMemory(data);
        auto pos = ds.findBackward(ZIP_END_OF_CENTRAL_DIR_SIG,
            ds.length - 4, 22 + 65535);
        assert(pos >= 0, "should find EOCD signature");
    }

    @("datasource: findBackward file")
    unittest {
        import darkarchive.formats.zip.types : ZIP_END_OF_CENTRAL_DIR_SIG;
        auto ds = DataSource.fromFile("test-data/test-zip.zip");
        auto pos = ds.findBackward(ZIP_END_OF_CENTRAL_DIR_SIG,
            ds.length - 4, 22 + 65535);
        assert(pos >= 0, "should find EOCD signature in file");
    }

    @("datasource: out-of-bounds read throws")
    unittest {
        import darkarchive.exception : DarkArchiveException;
        auto data = cast(const(ubyte)[]) "short";
        auto ds = DataSource.fromMemory(data);
        bool caught;
        try {
            ds.readSlice(0, 100);
        } catch (DarkArchiveException) {
            caught = true;
        }
        caught.shouldBeTrue;
    }
}
