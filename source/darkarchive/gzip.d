/// GZIP reader (RFC 1952 framing around std.zlib raw deflate).
module darkarchive.gzip;

import darkarchive.exception : DarkArchiveException;

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

/// Check if data starts with gzip magic bytes.
bool isGzip(const(ubyte)[] data) {
    return data.length >= 2 && data[0] == 0x1f && data[1] == 0x8b;
}

/// Check if a file starts with gzip magic bytes (reads only 2 bytes).
bool isGzipFile(string path) {
    import std.stdio : File;
    auto f = File(path, "rb");
    ubyte[2] magic;
    auto got = f.rawRead(magic[]);
    return got.length == 2 && magic[0] == 0x1f && magic[1] == 0x8b;
}


// ===========================================================================
// Unit tests
// ===========================================================================

version(unittest) {
    import unit_threaded.assertions : shouldEqual, shouldBeTrue;
    import darkarchive.formats.tar.reader : TarReader;

    private immutable testDataDir = "test-data";

    /// Plain .gz — single compressed file
    @("gzip read: plain gzip single file")
    unittest {
        import std.file : read;
        auto data = cast(const(ubyte)[]) read(testDataDir ~ "/test-single-file.gz");
        auto decompressed = gunzip(data);
        auto text = cast(string) decompressed;
        text.shouldEqual("This is a plain gzip compressed file, not a tar archive.\n");
    }

    /// Read tar.gz — decompress then parse tar
    @("gzip+tar read: tar.gz iterate and verify")
    unittest {
        import std.file : read;
        auto gzData = cast(const(ubyte)[]) read(testDataDir ~ "/test.tar.gz");
        auto tarData = gunzip(gzData);
        auto reader = TarReader(tarData);

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
        import std.file : read;
        auto gzData = cast(const(ubyte)[]) read(testDataDir ~ "/test-empty.tar.gz");
        auto tarData = gunzip(gzData);
        auto reader = TarReader(tarData);

        int count;
        foreach (entry; reader.entries) {
            count++;
        }
        count.shouldEqual(0);
    }

    /// Large entry from external tar.gz (128KB)
    @("gzip+tar read: 128KB file, multi-chunk")
    unittest {
        import std.file : read;
        auto gzData = cast(const(ubyte)[]) read(testDataDir ~ "/test-large-entry.tar.gz");
        auto tarData = gunzip(gzData);
        auto reader = TarReader(tarData);

        foreach (entry; reader.entries) {
            if (entry.pathname == "large-128k.bin") {
                entry.isFile.shouldBeTrue;
                auto data = reader.readData();
                data.length.shouldEqual(128 * 1024);
            }
        }
    }

    /// isGzip detection
    @("gzip: isGzip magic detection")
    unittest {
        import std.file : read;
        auto gzData = cast(const(ubyte)[]) read(testDataDir ~ "/test.tar.gz");
        isGzip(gzData).shouldBeTrue;

        auto zipData = cast(const(ubyte)[]) read(testDataDir ~ "/test-zip.zip");
        isGzip(zipData).shouldEqual(false);
    }

    /// Corrupted gzip data must be detected (CRC32 or inflate error)
    @("gzip security: corrupted data detected")
    unittest {
        import std.file : read;
        import darkarchive.exception : DarkArchiveException;

        auto data = (cast(ubyte[]) read(testDataDir ~ "/test-gzip-verify.gz")).dup;
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
        ubyte[10] header = [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xFF];
        bool caught;
        try {
            gunzip(header[]);
        } catch (Exception e) {
            caught = true;
        }
        caught.shouldBeTrue;
    }

    /// Streaming gzip decompression via GzipSequentialReader + TarReader
    @("gzip: streaming decompression via GzipSequentialReader")
    unittest {
        import darkarchive.datasource : GzipSequentialReader;

        auto gzStream = new GzipSequentialReader(testDataDir ~ "/test.tar.gz");
        auto reader = TarReader(gzStream);
        string[] names;
        foreach (entry; reader.entries) {
            names ~= entry.pathname;
            if (entry.pathname == "./file1.txt")
                reader.readText().shouldEqual("Hello from file1\n");
        }
        assert(names.length > 0, "should find entries via streaming gzip");
    }

    /// Memory consistency: streaming through tar.gz should not accumulate memory
    @("gzip: streaming does not accumulate memory")
    unittest {
        import darkarchive.formats.tar.writer : TarWriter, gzipCompress;
        import darkarchive.datasource : GzipSequentialReader;
        import core.memory : GC;

        // Create tar.gz with many entries totaling ~1MB
        auto tw = TarWriter.create();
        auto chunk = new ubyte[](4096); // 4KB per entry
        foreach (i; 0 .. 256) { // 256 * 4KB = 1MB total
            import std.format : format;
            tw.addBuffer("entry_%04d.bin".format(i), chunk);
        }
        auto gzData = gzipCompress(tw.data);

        // Write to temp file
        import std.file : write, remove, exists;
        auto tmpPath = "test-data/test-mem-consistency.tar.gz";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        write(tmpPath, gzData);

        // Force GC before measuring
        GC.collect();
        auto memBefore = GC.stats.usedSize;

        // Stream through all entries, reading each via chunked API
        auto gzStream = new GzipSequentialReader(tmpPath);
        auto reader = TarReader(gzStream);
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
