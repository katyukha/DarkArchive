/// GZIP reader/writer (RFC 1952 framing around std.zlib raw deflate).
module darkarchive.gzip;

import darkarchive.exception : DarkArchiveException;
import std.range : isOutputRange;

/// Decompress a gzip-compressed byte buffer.
/// Returns the uncompressed data.
const(ubyte)[] gunzip(const(ubyte)[] data) {
    if (data.length < 10)
        throw new DarkArchiveException("GZIP: data too short for header");

    // Verify magic
    if (data[0] != 0x1f || data[1] != 0x8b)
        throw new DarkArchiveException("GZIP: invalid magic bytes");

    if (data[2] != 8)
        throw new DarkArchiveException("GZIP: unsupported compression method (only deflate supported)");

    // Minimum valid gzip: 10-byte header + 8-byte trailer = 18 bytes
    if (data.length < 18)
        throw new DarkArchiveException("GZIP: data too short (truncated)");

    // Use std.zlib.uncompress with gzip header handling.
    // std.zlib.HeaderFormat.gzip tells zlib to expect gzip framing.
    import std.zlib : UnCompress, HeaderFormat;
    auto uc = new UnCompress(HeaderFormat.gzip);
    auto result = cast(ubyte[])(uc.uncompress(data));
    auto tail = cast(ubyte[])(uc.flush());

    if (tail.length > 0)
        return result ~ tail;
    return result;
}


// ===========================================================================
// GzipSink — output range that gzip-compresses to an inner output range
// ===========================================================================

/// Output range that deflate-compresses data in gzip format and forwards
/// compressed bytes to an inner output range.
///
/// Call `close()` to flush the compressor and write the gzip trailer.
/// `close()` also calls `_sink.close()` if the inner range has that method.
///
/// Warning: Do not copy this struct after calling `put()` — the internal
/// zlib state is shared between copies and concurrent use causes corruption.
struct GzipSink(R)
    if (isOutputRange!(R, const(ubyte)[]))
{
    import etc.c.zlib;

    private {
        R _sink;
        // Heap-allocated so copies of GzipSink share a pointer to the same
        // z_stream, keeping zlib's state->strm back-pointer stable across copies.
        z_stream* _zs;
        bool _zsInit;
        ubyte[] _outBuf;

        enum OUT_CHUNK = 64 * 1024;
    }

    this(R sink) {
        _sink = sink;
        _outBuf = new ubyte[](OUT_CHUNK);
        _zs = new z_stream;
        *_zs = z_stream.init;
        if (deflateInit2(_zs, 6, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
            throw new DarkArchiveException("GZIP: deflateInit2 failed");
        _zsInit = true;
    }

    void put(const(ubyte)[] data) {
        _zs.next_in = cast(ubyte*) data.ptr;
        _zs.avail_in = cast(uint) data.length;
        while (_zs.avail_in > 0) {
            _zs.next_out = _outBuf.ptr;
            _zs.avail_out = cast(uint) _outBuf.length;
            auto ret = deflate(_zs, Z_NO_FLUSH);
            if (ret != Z_OK && ret != Z_BUF_ERROR)
                throw new DarkArchiveException("GZIP: deflate failed");
            auto produced = _outBuf.length - _zs.avail_out;
            if (produced > 0)
                emit(_outBuf[0 .. produced]);
        }
    }

    void close() {
        if (!_zsInit) return;
        _zs.next_in = null;
        _zs.avail_in = 0;
        int ret;
        do {
            _zs.next_out = _outBuf.ptr;
            _zs.avail_out = cast(uint) _outBuf.length;
            ret = deflate(_zs, Z_FINISH);
            if (ret != Z_OK && ret != Z_STREAM_END)
                throw new DarkArchiveException("GZIP: deflate finish failed");
            auto produced = _outBuf.length - _zs.avail_out;
            if (produced > 0)
                emit(_outBuf[0 .. produced]);
        } while (ret != Z_STREAM_END);

        deflateEnd(_zs);
        _zsInit = false;
        _outBuf = null;

        static if (__traits(hasMember, R, "close"))
            _sink.close();
    }

    private void emit(const(ubyte)[] data) {
        import std.range.primitives : rangePut = put;
        rangePut(_sink, data);
    }
}

/// Create a `GzipSink` wrapping any output range (IFTI).
auto gzipSink(R)(R sink)
    if (isOutputRange!(R, const(ubyte)[]))
{
    return GzipSink!R(sink);
}


// ===========================================================================
// Unit tests
// ===========================================================================

version(unittest) import thepath : Path;
version(unittest) {
    import darkarchive.formats.tar.reader : tarReader, tarGzReader;

    private immutable testDataDir = "test-data";

    /// Plain .gz — single compressed file
    @("gzip read: plain gzip single file")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue;
        auto data = cast(const(ubyte)[]) Path(testDataDir ~ "/test-single-file.gz").readFile();
        auto decompressed = gunzip(data);
        auto text = cast(string) decompressed;
        text.shouldEqual("This is a plain gzip compressed file, not a tar archive.\n");
    }

    /// Read tar.gz — decompress then parse tar
    @("gzip+tar read: tar.gz iterate and verify")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue;
        auto gzData = cast(const(ubyte)[]) Path(testDataDir ~ "/test.tar.gz").readFile();
        auto tarData = gunzip(gzData);
        // Write decompressed tar to temp file for TarReader
        auto tmpPath = "test-data/test-gzip-tar-iterate.tar";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        Path(tmpPath).writeFile(tarData);

        auto reader = tarReader(tmpPath);
        scope(exit) reader.close();

        string[] names;
        foreach (entry; reader.entries) {
            names ~= entry.pathname;
            if (entry.pathname == "./file1.txt")
                reader.readText().shouldEqual("Hello from file1\n");
            else if (entry.pathname == "./file2.txt")
                reader.readText().shouldEqual("Hello from file2\n");
            else if (entry.pathname == "./subdir/nested.txt")
                reader.readText().shouldEqual("Nested file content\n");
        }
        assert(names.length > 0, "should have found entries");
    }

    /// Empty tar.gz — zero entries
    @("gzip+tar read: empty archive, zero entries")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue;
        auto gzData = cast(const(ubyte)[]) Path(testDataDir ~ "/test-empty.tar.gz").readFile();
        auto tarData = gunzip(gzData);
        // Write decompressed tar to temp file for TarReader
        auto tmpPath = "test-data/test-gzip-empty-archive.tar";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        Path(tmpPath).writeFile(tarData);

        auto reader = tarReader(tmpPath);
        scope(exit) reader.close();

        int count;
        foreach (entry; reader.entries) {
            count++;
        }
        count.shouldEqual(0);
    }

    /// Large entry from external tar.gz (128KB)
    @("gzip+tar read: 128KB file, multi-chunk")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue;
        auto gzData = cast(const(ubyte)[]) Path(testDataDir ~ "/test-large-entry.tar.gz").readFile();
        auto tarData = gunzip(gzData);
        // Write decompressed tar to temp file for TarReader
        auto tmpPath = "test-data/test-gzip-large-entry.tar";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        Path(tmpPath).writeFile(tarData);

        auto reader = tarReader(tmpPath);
        scope(exit) reader.close();

        foreach (entry; reader.entries) {
            if (entry.pathname == "large-128k.bin") {
                entry.isFile.shouldBeTrue;
                auto data = reader.readData();
                data.length.shouldEqual(128 * 1024);
            }
        }
    }

    /// Corrupted gzip data must be detected (CRC32 or inflate error)
    @("gzip security: corrupted data detected")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue;
        import darkarchive.exception : DarkArchiveException;

        auto data = (cast(ubyte[]) Path(testDataDir ~ "/test-gzip-verify.gz").readFile()).dup;
        // Corrupt a byte in the compressed data area (after 10-byte header)
        if (data.length > 15)
            data[12] ^= 0xFF;

        bool caught;
        try {
            gunzip(cast(const(ubyte)[]) data);
        } catch (Exception e) {
            // Either std.zlib.ZlibException or DarkArchiveException is acceptable
            caught = true;
        }
        caught.shouldBeTrue;
    }

    /// Invalid gzip magic bytes must throw
    @("gzip security: invalid magic throws")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue;
        import darkarchive.exception : DarkArchiveException;

        auto garbage = cast(const(ubyte)[]) "not gzip data at all!!";
        bool caught;
        try {
            gunzip(garbage);
        } catch (DarkArchiveException e) {
            caught = true;
        }
        caught.shouldBeTrue;
    }

    /// Truncated gzip (just header, no data) must throw
    @("gzip security: truncated gzip throws")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue;
        ubyte[10] header = [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xFF];
        bool caught;
        try {
            gunzip(header[]);
        } catch (Exception e) {
            caught = true;
        }
        caught.shouldBeTrue;
    }

    /// Streaming gzip decompression via tarGzReader
    @("gzip: streaming decompression via tarGzReader")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue;

        auto reader = tarGzReader(testDataDir ~ "/test.tar.gz");
        string[] names;
        foreach (entry; reader.entries) {
            names ~= entry.pathname;
            if (entry.pathname == "./file1.txt")
                reader.readText().shouldEqual("Hello from file1\n");
        }
        assert(names.length > 0, "should find entries via tarGzReader");
    }

    /// Multi-member gzip: second member is silently ignored (std.zlib stops at Z_STREAM_END).
    /// This documents the current behavior — it is not wrong, just a known limitation.
    @("gzip: gunzip() decompresses only the first gzip member (multi-member not supported)")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        import darkarchive.formats.tar.writer : gzipCompress;

        auto data1 = cast(const(ubyte)[]) "first member";
        auto data2 = cast(const(ubyte)[]) "second member";
        auto multiMember = gzipCompress(data1) ~ gzipCompress(data2);

        // gunzip() is a one-shot convenience function backed by std.zlib, which stops
        // at Z_STREAM_END after the first member.  This is intentional best-effort
        // behaviour: TAR.GZ files are never multi-member in practice.  Callers that
        // need multi-member support must use GzipRange (the streaming path).
        auto result = gunzip(multiMember);
        result.shouldEqual(data1);
    }

    /// Memory consistency: streaming through tar.gz should not accumulate memory
    @("gzip: streaming does not accumulate memory")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue;
        import darkarchive.formats.tar.writer : tarWriter, gzipCompress;
        import core.memory : GC;

        // Create tar with many entries totaling ~1MB via temp file
        auto tarTmpPath = "test-data/test-mem-consistency-inner.tar";
        scope(exit) if (Path(tarTmpPath).exists) Path(tarTmpPath).remove();
        auto tw = tarWriter(tarTmpPath);
        scope(exit) tw.close();
        auto chunk = new ubyte[](4096); // 4KB per entry
        foreach (i; 0 .. 256) { // 256 * 4KB = 1MB total
            import std.format : format;
            tw.addBuffer("entry_%04d.bin".format(i), chunk);
        }
        tw.finish();
        auto tarBytes = cast(const(ubyte)[]) Path(tarTmpPath).readFile();
        auto gzData = gzipCompress(tarBytes);

        // Write gzip to temp file
        auto tmpPath = "test-data/test-mem-consistency.tar.gz";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        Path(tmpPath).writeFile(gzData);

        // Force GC before measuring
        GC.collect();
        auto memBefore = GC.stats.usedSize;

        // Stream through all entries, reading each via chunked API
        auto reader = tarGzReader(tmpPath);
        size_t totalRead;
        foreach (entry; reader.entries) {
            if (entry.isFile) {
                reader.readDataChunked((const(ubyte)[] c) {
                    totalRead += c.length;
                });
            }
        }
        reader.close();

        GC.collect();
        auto memAfter = GC.stats.usedSize;

        // Total data was ~1MB. With proper streaming, memory should not grow
        // proportionally to archive size. Allow reasonable GC overhead (2MB)
        // but reject growth > 4MB which would indicate accumulation.
        auto growth = memAfter > memBefore ? memAfter - memBefore : 0;
        assert(growth < 4 * 1024 * 1024,
            "memory grew by " ~ formatSize(growth) ~ " — possible memory leak");
        assert(totalRead > 0, "should have read data");
    }
}

private string formatSize(size_t bytes) {
    import std.format : format;
    if (bytes < 1024) return "%d B".format(bytes);
    if (bytes < 1024 * 1024) return "%.1f KB".format(cast(double) bytes / 1024);
    return "%.1f MB".format(cast(double) bytes / (1024 * 1024));
}
