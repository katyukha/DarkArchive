/// High-level format-parameterized archive reader and writer.
///
/// `DarkArchiveReader!(fmt)` and `DarkArchiveWriter!(fmt)` are templates over
/// `DarkArchiveFormat`. The format is a compile-time parameter — format
/// capability mismatches (e.g. streaming ZIP) become compile-time errors rather
/// than runtime throws.
///
/// For runtime format detection use `probeArchive`, then dispatch with
/// `final switch`.
module darkarchive.archive;

import std.conv : octal;

import darkarchive.entry : DarkArchiveEntry, EntryType;
import darkarchive.exception : DarkArchiveException;
import darkarchive.formats.zip : ZipReader, ZipWriter;
import darkarchive.formats.tar : TarReader, TarWriter, tarWriter, tarGzWriter;
import darkarchive.datasource : chunkSource, DelegateSink, FileChunkSource,
    ChunkReader, GzipRange;
import darkarchive.gzip : GzipSink;

import thepath : Path;


/// Archive format.
enum DarkArchiveFormat {
    zip,
    tar,
    tarGz,
    // tarZst,  -- future stage
}

/// Optional capabilities that vary by format (for runtime queries via supports()).
enum ArchiveCapability {
    streamingRead,    /// Can stream from any input range (TAR/TARGZ via darkArchiveReader)
    streamingWrite,   /// Can stream to any output range (TAR/TARGZ via darkArchiveWriter)
    randomAccessRead  /// Can seek to arbitrary entries (e.g. ZIP central directory)
}

/// Query whether a format supports a given capability at runtime.
/// Prefer static asserts and template constraints for compile-time checks.
bool supports(DarkArchiveFormat fmt, ArchiveCapability cap) {
    final switch (cap) {
        case ArchiveCapability.streamingRead:
            final switch (fmt) {
                case DarkArchiveFormat.zip:   return false;
                case DarkArchiveFormat.tar:   return true;
                case DarkArchiveFormat.tarGz: return true;
            }
        case ArchiveCapability.streamingWrite:
            final switch (fmt) {
                case DarkArchiveFormat.zip:   return false;
                case DarkArchiveFormat.tar:   return true;
                case DarkArchiveFormat.tarGz: return true;
            }
        case ArchiveCapability.randomAccessRead:
            final switch (fmt) {
                case DarkArchiveFormat.zip:   return true;
                case DarkArchiveFormat.tar:   return false;
                case DarkArchiveFormat.tarGz: return false;
            }
    }
}

/// Extract behavior flags.
enum DarkExtractFlags {
    none        = 0,
    securePaths = 1,
    symlinks    = 2,
    defaults    = securePaths,
}

/// Controls symlink handling in addTree.
enum FollowSymlinks {
    yes,  /// Follow symlinks, archive target content as regular file (default)
    no,   /// Preserve symlinks as symlink entries (Posix only)
}

/// Parameters passed to extractTo preprocessing delegate.
struct ExtractParams {
    string destPath;
    const(DarkArchiveEntry)* sourceEntry;
}

/// Hard limits enforced during extraction.
struct ExtractionLimits {
    ulong maxTotalBytes = ulong.max;
    ulong maxEntryBytes = ulong.max;
    ulong maxEntries    = ulong.max;
}


// ---------------------------------------------------------------------------
// probeArchive
// ---------------------------------------------------------------------------

/// Detect the archive format of a file by reading its magic bytes.
DarkArchiveFormat probeArchive(string path) {
    auto p = Path(path);
    auto fileSize = p.getSize();
    if (fileSize < 4)
        throw new DarkArchiveException("Archive file too small to detect format");
    auto headerLen = fileSize > 264 ? 264 : cast(size_t) fileSize;
    return probeArchive(cast(const(ubyte)[]) p.readFile(headerLen));
}

/// ditto — probe from a pre-read header byte slice (at least 4 bytes required).
DarkArchiveFormat probeArchive(const(ubyte)[] header) {
    if (header.length < 4)
        throw new DarkArchiveException("Archive header too small to detect format");

    if (header[0] == 'P' && header[1] == 'K' &&
        (header[2] == 3 || header[2] == 5))
        return DarkArchiveFormat.zip;

    if (header[0] == 0x1f && header[1] == 0x8b)
        return DarkArchiveFormat.tarGz;

    if (header.length >= 262 &&
        header[257 .. 262] == cast(const(ubyte)[]) "ustar")
        return DarkArchiveFormat.tar;

    throw new DarkArchiveException("Cannot detect archive format");
}


// ---------------------------------------------------------------------------
// Range-based factory functions
// ---------------------------------------------------------------------------

/// Create a TAR or TAR.GZ reader from any input range of `const(ubyte)[]` chunks.
///
/// ZIP is not supported via this function (requires random-access file).
/// Use `DarkArchiveReader!(DarkArchiveFormat.zip)(path)` for ZIP.
///
/// Returns the raw `TarReader` template instantiation — callers get the full
/// `entries`, `readText`, `skipData`, `readDataChunked`, `close` API.
auto darkArchiveReader(DarkArchiveFormat fmt, R)(R source)
    if (fmt != DarkArchiveFormat.zip)
{
    import std.range : isInputRange, ElementType;
    import darkarchive.formats.tar.reader : tarReader;
    static assert(isInputRange!R && is(ElementType!R : const(ubyte)[]),
        "darkArchiveReader: R must be an input range of const(ubyte)[] chunks");
    static if (fmt == DarkArchiveFormat.tar)
        return tarReader(source);
    else // tarGz
    {
        import darkarchive.datasource : gzipRange;
        return tarReader(gzipRange(source));
    }
}

/// Create a TAR or TAR.GZ writer to any output range of `const(ubyte)[]`.
///
/// ZIP is not supported via this function.
/// Use `DarkArchiveWriter!(DarkArchiveFormat.zip)(path)` for ZIP.
///
/// Returns the raw `TarWriter` template instantiation — callers get the full
/// `addBuffer`, `addDirectory`, `addSymlink`, `addStream`, `finish`, `close` API.
auto darkArchiveWriter(DarkArchiveFormat fmt, R)(R sink)
    if (fmt != DarkArchiveFormat.zip)
{
    import std.range : isOutputRange;
    static assert(isOutputRange!(R, const(ubyte)[]),
        "darkArchiveWriter: R must be an output range of const(ubyte)[]");
    return DarkArchiveWriter!(fmt, R)(sink);
}


// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

private bool hasPathTraversal(string path) {
    import std.algorithm : splitter;
    foreach (component; path.splitter('/')) {
        if (component == "..")
            return true;
        foreach (sub; component.splitter('\\'))
            if (sub == "..")
                return true;
    }
    return false;
}


private void applyFilePermissions(string path, uint archivePerms) {
    version(Posix) {
        if (archivePerms == 0) return;
        auto safeBits = archivePerms & octal!777;
        safeBits &= ~octal!22;
        if (safeBits == 0) return;
        import std.file : setAttributes;
        try { setAttributes(path, safeBits); } catch (Exception) {}
    }
}

private void verifyPathWithinRoot(string path, string root) {
    auto resolved = resolveRealPath(path);
    auto normalRoot = resolveRealPath(root);
    if (!Path(resolved).isInside(Path(normalRoot)))
        throw new DarkArchiveException(
            "Refusing to write file: resolved path escapes extraction directory");
}

private string resolveRealPath(string path) {
    version(Posix) {
        // toAbsolute() = buildNormalizedPath(absolutePath(expandTilde(path)))
        auto abs = Path(path).toAbsolute();
        Path existing = abs;
        string[] tail;
        // Walk up to the longest existing prefix: Path.realPath() (POSIX realpath(3))
        // throws ErrnoException on non-existent paths.  Files not yet extracted
        // won't exist, so we must find what IS on disk first.
        while (!existing.isRoot && !existing.exists) {
            tail = existing.baseName ~ tail;
            existing = existing.parent;
        }
        if (!existing.exists)
            return abs.toString();
        try {
            auto realBase = existing.realPath();
            return (tail.length == 0 ? realBase : realBase.join(tail)).toString();
        } catch (Exception) {
            return abs.toString();
        }
    } else {
        return Path(path).toAbsolute().toString();
    }
}


private string formatMemSize(ulong bytes) {
    import std.format : format;
    if (bytes >= 1024 * 1024)
        return format!"%.1f MB"(bytes / (1024.0 * 1024));
    if (bytes >= 1024)
        return format!"%.1f KB"(bytes / 1024.0);
    return format!"%d B"(bytes);
}


// ---------------------------------------------------------------------------
// DarkArchiveItemReader / DarkArchiveItem
// ---------------------------------------------------------------------------

/// Data accessor for a single archive entry — obtained via `DarkArchiveItem.data`.
///
/// For TAR and TAR.GZ this is only valid during the current `foreach` iteration
/// step; calling read methods after `popFront` is undefined behaviour.
/// For ZIP the accessor is position-independent (random access), but the same
/// rule should be assumed for portability.
///
/// Non-copyable by design: copy `item.meta` (a plain `DarkArchiveEntry`) if you
/// need to retain metadata across iterations.
struct DarkArchiveItemReader(DarkArchiveFormat fmt) {
    private DarkArchiveReader!fmt* _parent;
    static if (fmt == DarkArchiveFormat.zip)
        private size_t _idx;

    @disable this(this);

    /// Read the full entry data into memory.
    ubyte[] readAll() {
        static if (fmt == DarkArchiveFormat.zip)
            return cast(ubyte[]) _parent._reader.readData(_idx).dup;
        else {
            auto d = _parent._reader.readData();
            return d is null ? [] : cast(ubyte[]) d;
        }
    }

    /// Convenience: readAll as a UTF-8 string.
    string readText() { return cast(string) readAll(); }

    /// Stream entry data in chunks without buffering the full entry in memory.
    void readChunks(scope void delegate(const(ubyte)[] chunk) sink,
                     size_t chunkSize = 8192) {
        static if (fmt == DarkArchiveFormat.zip)
            _parent._reader.readDataChunked(_idx, sink, chunkSize);
        else
            _parent._reader.readDataChunked(sink, chunkSize);
    }
}

/// A single archive entry as yielded by `DarkArchiveReader.entries()`.
///
/// `meta` holds the entry metadata (`DarkArchiveEntry` — pathname, size, type …).
/// `data` is the data accessor; call `data.readAll()`, `data.readText()`, or
/// `data.readChunks(sink)` to consume the entry's bytes.
///
/// Non-copyable.  To retain metadata past the current iteration, copy `item.meta`:
/// ---
/// DarkArchiveEntry saved;
/// foreach (ref item; reader.entries)
///     if (item.meta.isFile) saved = item.meta;
/// ---
struct DarkArchiveItem(DarkArchiveFormat fmt) {
    DarkArchiveEntry          meta;
    DarkArchiveItemReader!fmt data;

    @disable this(this);
}


// ---------------------------------------------------------------------------
// DarkArchiveReader
// ---------------------------------------------------------------------------

/// High-level archive reader parameterized on format.
///
/// `DarkArchiveReader!(DarkArchiveFormat.zip)` uses file-backed random access.
/// `DarkArchiveReader!(DarkArchiveFormat.tar)` streams sequentially from file.
/// `DarkArchiveReader!(DarkArchiveFormat.tarGz)` streams through gzip decompression.
///
/// TAR and TAR.GZ additionally support a streaming delegate constructor.
/// ZIP does not — attempting to instantiate it is a compile-time error.
struct DarkArchiveReader(DarkArchiveFormat fmt) {
    static if (fmt == DarkArchiveFormat.zip) {
        private ZipReader* _reader;
    } else static if (fmt == DarkArchiveFormat.tar) {
        private TarReader!(ChunkReader!FileChunkSource)* _reader;
    } else { // tarGz
        private TarReader!(ChunkReader!(GzipRange!FileChunkSource))* _reader;
    }

    /// The archive format — a compile-time constant.
    enum DarkArchiveFormat format = fmt;

    @disable this();

    this(in Path path) { this(path.toString()); }

    /// Open from file path.
    this(string path) {
        static if (fmt == DarkArchiveFormat.zip) {
            _reader = new ZipReader(path);
        } else static if (fmt == DarkArchiveFormat.tar) {
            auto cr = ChunkReader!FileChunkSource(FileChunkSource(path));
            _reader = new typeof(*_reader)(cr);
        } else {
            alias CR = ChunkReader!(GzipRange!FileChunkSource);
            auto cr = CR(GzipRange!FileChunkSource(FileChunkSource(path)));
            _reader = new typeof(*_reader)(cr);
        }
    }

    void close() { _reader.close(); }

    /// Iterate over entries.
    auto entries() { return EntryRange(&this); }

    // -- processEntries --

    /// Process all entries, calling processor for each.
    size_t processEntries(
            scope void delegate(scope ref DarkArchiveItem!fmt item) processor) {
        size_t count;
        foreach (ref item; entries()) {
            processor(item);
            count++;
        }
        return count;
    }

    /// Process specific entries by pathname. Stops early when all are found.
    size_t processEntries(
            const(string)[] names,
            scope void delegate(scope ref DarkArchiveItem!fmt item) processor) {
        if (names.length == 0) return 0;
        bool[string] remaining;
        foreach (name; names) remaining[name] = true;
        size_t count;
        foreach (ref item; entries()) {
            if (item.meta.pathname in remaining) {
                processor(item);
                count++;
                remaining.remove(item.meta.pathname);
                if (remaining.length == 0) break;
            }
        }
        return count;
    }

    // -- extractTo --

    void extractTo(in Path destination,
                    DarkExtractFlags flags = DarkExtractFlags.defaults,
                    ExtractionLimits limits = ExtractionLimits.init) {
        extractToImpl(destination, flags, limits, null);
    }

    void extractTo(in Path destination,
                    DarkExtractFlags flags,
                    scope bool delegate(ref ExtractParams params) preprocess) {
        extractToImpl(destination, flags, ExtractionLimits.init, preprocess);
    }

    void extractTo(in Path destination,
                    DarkExtractFlags flags,
                    ExtractionLimits limits,
                    scope bool delegate(ref ExtractParams params) preprocess) {
        extractToImpl(destination, flags, limits, preprocess);
    }

    private void extractToImpl(
            in Path destination,
            DarkExtractFlags flags,
            ExtractionLimits limits,
            scope bool delegate(ref ExtractParams params) preprocess) {
        import std.format : format;

        auto destStr = destination.toString();
        ulong totalBytes;
        ulong entryCount;

        foreach (ref item; entries()) {
            ExtractParams params;
            params.destPath = item.meta.pathname;
            params.sourceEntry = &item.meta;

            if (preprocess !is null) {
                if (!preprocess(params)) continue; // popFront auto-skips data
            }

            entryCount++;
            if (entryCount > limits.maxEntries)
                throw new DarkArchiveException(
                    "Extraction limit exceeded: too many entries (max %d)".format(limits.maxEntries));

            auto entryPath = params.destPath;

            // NUL bytes in filenames are never valid — reject unconditionally
            // regardless of securePaths flag.  Detection here (not at open/read
            // time) lets callers still list or inspect entries before extracting.
            foreach (c; entryPath)
                if (c == '\0')
                    throw new DarkArchiveException(
                        "Refusing to extract entry: filename contains NUL byte");

            if (flags & DarkExtractFlags.securePaths) {
                if (entryPath.length > 0 && entryPath[0] == '/')
                    throw new DarkArchiveException(
                        "Refusing to extract absolute path: " ~ entryPath);
                if (hasPathTraversal(entryPath))
                    throw new DarkArchiveException(
                        "Refusing to extract path with '..' component: " ~ entryPath);
            }

            if (entryPath.length >= 2 && entryPath[0 .. 2] == "./")
                entryPath = entryPath[2 .. $];
            if (entryPath.length == 0) continue; // popFront auto-skips data

            auto fullPath = Path(destStr, entryPath);

            if (item.meta.isDir) {
                fullPath.mkdir(true);
                // dirs have no data — popFront auto-skips
            } else if (item.meta.isSymlink) {
                if (!(flags & DarkExtractFlags.symlinks)) continue;
                auto target = item.meta.symlinkTarget;
                if (target.length > 0 && target[0] == '/')
                    throw new DarkArchiveException(
                        "Refusing to create symlink with absolute target: " ~ target);
                if (flags & DarkExtractFlags.securePaths) {
                    if (hasPathTraversal(target))
                        throw new DarkArchiveException(
                            "Refusing to create symlink with '..' in target: " ~ target);
                }
                auto parent = fullPath.parent;
                if (!parent.exists)
                    parent.mkdir(true);
                version(Posix) {
                    Path(item.meta.symlinkTarget).symlink(fullPath);
                } else {
                    throw new DarkArchiveException(
                        "Symlink extraction is not supported on this platform: " ~ entryPath);
                }
                // symlinks have no data — popFront auto-skips
            } else if (item.meta.isHardlink) {
                if (!(flags & DarkExtractFlags.symlinks)) continue;
                auto target = item.meta.symlinkTarget;
                if (target.length > 0 && target[0] == '/')
                    throw new DarkArchiveException(
                        "Refusing to create hardlink with absolute target: " ~ target);
                if (flags & DarkExtractFlags.securePaths) {
                    if (hasPathTraversal(target))
                        throw new DarkArchiveException(
                            "Refusing to create hardlink with '..' in target: " ~ target);
                }
                version(Posix) {
                    import core.sys.posix.unistd : posixLink = link;
                    import std.string : toStringz;
                    auto targetFull = destStr ~ "/" ~ target;
                    if (flags & DarkExtractFlags.securePaths)
                        verifyPathWithinRoot(targetFull, destStr);
                    auto parent = fullPath.parent;
                    if (!parent.exists)
                        parent.mkdir(true);
                    if (posixLink(targetFull.toStringz, fullPath.toString.toStringz) != 0)
                        throw new DarkArchiveException(
                            "Failed to create hardlink: " ~ fullPath.toString);
                } else {
                    throw new DarkArchiveException(
                        "Hardlink extraction is not supported on this platform: " ~ entryPath);
                }
                // hardlinks have no data — popFront auto-skips
            } else {
                auto parent = fullPath.parent;
                if (!parent.exists)
                    parent.mkdir(true);
                if (flags & DarkExtractFlags.securePaths)
                    verifyPathWithinRoot(parent.toString(), destStr);
                extractEntryToFile(item.data, fullPath.toString(), limits, totalBytes);
                applyFilePermissions(fullPath.toString(), item.meta.permissions);
            }
        }
    }

    private void extractEntryToFile(ref DarkArchiveItemReader!fmt dataReader,
                                     string outPath, ExtractionLimits limits,
                                     ref ulong totalBytes) {
        import std.stdio : File;
        import std.format : format;
        auto f = File(outPath, "wb");
        ulong entryBytes;
        dataReader.readChunks((const(ubyte)[] chunk) {
            entryBytes += chunk.length;
            totalBytes += chunk.length;
            if (entryBytes > limits.maxEntryBytes)
                throw new DarkArchiveException(
                    "Extraction limit exceeded: entry exceeds %s bytes"
                    .format(limits.maxEntryBytes));
            if (totalBytes > limits.maxTotalBytes)
                throw new DarkArchiveException(
                    "Extraction limit exceeded: total extracted bytes exceed %s"
                    .format(limits.maxTotalBytes));
            f.rawWrite(chunk);
        });
    }

    // -- EntryRange --

    private static struct EntryRange {
        private DarkArchiveReader!fmt* _parent;
        private DarkArchiveItem!fmt _current;

        // Non-copyable because DarkArchiveItem is non-copyable.
        @disable this(this);

        static if (fmt == DarkArchiveFormat.zip) {
            private size_t _idx;
            private size_t _len;

            this(DarkArchiveReader!fmt* parent) {
                _parent = parent;
                _idx = 0;
                _len = parent._reader.length;
                _current.data._parent = parent;
                if (!empty) _loadCurrent();
            }

            bool empty() { return _idx >= _len; }

            ref DarkArchiveItem!fmt front() { return _current; }

            void popFront() {
                _idx++;
                if (!empty) _loadCurrent();
            }

            private void _loadCurrent() {
                _current.meta = _parent._reader.entryAt(_idx);
                _current.data._idx = _idx;
            }

        } else {
            static if (fmt == DarkArchiveFormat.tar)
                alias TarReaderT = TarReader!(ChunkReader!FileChunkSource);
            else
                alias TarReaderT = TarReader!(ChunkReader!(GzipRange!FileChunkSource));

            private TarReaderT.EntryRange _range;

            this(DarkArchiveReader!fmt* parent) {
                _parent = parent;
                _range = parent._reader.entries();
                _current.data._parent = parent;
                if (!empty) _current.meta = _range.front();
            }

            bool empty() { return _range.empty(); }

            ref DarkArchiveItem!fmt front() { return _current; }

            void popFront() {
                _range.popFront();
                if (!empty) _current.meta = _range.front();
            }
        }
    }
}


// ---------------------------------------------------------------------------
// DarkArchiveWriter
// ---------------------------------------------------------------------------

/// High-level archive writer parameterized on format and (optionally) sink type.
///
/// `DarkArchiveWriter!(fmt)` writes to a file path (default, `SinkT = void`).
/// `DarkArchiveWriter!(fmt, R)` writes to any output range `R` of `const(ubyte)[]`.
/// Use the `darkArchiveWriter(fmt, sink)` factory to construct the sink-backed form
/// without spelling out the sink type.
///
/// ZIP format does not support output-range sinks (requires random access for the
/// central directory). Attempting to instantiate `DarkArchiveWriter!(zip, R)` is
/// a compile-time error.
struct DarkArchiveWriter(DarkArchiveFormat fmt, SinkT = void) {

    private alias Self = DarkArchiveWriter!(fmt, SinkT);

    // Internal writer type depends on whether we are file-backed or sink-backed.
    static if (is(SinkT == void)) {
        // File-backed: delegate sink wraps a heap-allocated File.
        static if (fmt == DarkArchiveFormat.zip)
            private ZipWriter* _writer;
        else static if (fmt == DarkArchiveFormat.tar)
            private TarWriter!DelegateSink* _writer;
        else // tarGz
            private TarWriter!(GzipSink!DelegateSink)* _writer;
    } else {
        // Sink-backed: caller supplies any isOutputRange!(R, const(ubyte)[]).
        static assert(fmt != DarkArchiveFormat.zip,
            "ZIP format requires random access — output-range sink is not supported. "
            ~ "Use DarkArchiveWriter!(DarkArchiveFormat.zip)(path) instead.");
        import std.range : isOutputRange;
        static assert(isOutputRange!(SinkT, const(ubyte)[]),
            "SinkT must satisfy isOutputRange!(SinkT, const(ubyte)[])");
        static if (fmt == DarkArchiveFormat.tar)
            private TarWriter!SinkT* _writer;
        else // tarGz
            private TarWriter!(GzipSink!SinkT)* _writer;
    }

    private bool _finished;
    private string _filePath;   // non-null only for file-backed writers

    @disable this();

    // -----------------------------------------------------------------------
    // File-backed constructors (only available when SinkT == void)
    // -----------------------------------------------------------------------

    static if (is(SinkT == void)) {

        this(in Path path) { this(path.toString()); }

        /// Create writer to file.  Format is inferred from the template parameter.
        this(string path) {
            _filePath = path;
            static if (fmt == DarkArchiveFormat.zip) {
                _writer = new ZipWriter();
                *_writer = ZipWriter.createToFile(path);
            } else static if (fmt == DarkArchiveFormat.tar) {
                import std.stdio : File;
                auto f = new File(path, "wb");
                _writer = new TarWriter!DelegateSink(DelegateSink(
                    (const(ubyte)[] data) { f.rawWrite(data); },
                    () { f.close(); }
                ));
            } else { // tarGz
                import std.stdio : File;
                auto f = new File(path, "wb");
                auto fsink = DelegateSink(
                    (const(ubyte)[] data) { f.rawWrite(data); },
                    () { f.close(); }
                );
                _writer = new TarWriter!(GzipSink!DelegateSink)(
                    GzipSink!DelegateSink(fsink)
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Sink-backed constructor (only available when SinkT != void)
    // -----------------------------------------------------------------------

    static if (!is(SinkT == void)) {

        /// Create writer streaming to `sink`.  Call `finish()` when done.
        this(SinkT sink) {
            static if (fmt == DarkArchiveFormat.tar)
                _writer = new TarWriter!SinkT(sink);
            else // tarGz
                _writer = new TarWriter!(GzipSink!SinkT)(GzipSink!SinkT(sink));
        }
    }

    // -----------------------------------------------------------------------
    // Entry-adding methods — identical for both file-backed and sink-backed
    // -----------------------------------------------------------------------

    /// Add file from disk.
    ref Self add(in Path sourcePath, string archiveName = null) return {
        return add(sourcePath.toString(), archiveName);
    }

    /// ditto
    ref Self add(string sourcePath, string archiveName = null) return {
        import std.stdio : File;
        if (archiveName is null)
            archiveName = Path(sourcePath).baseName;
        auto fileSize = Path(sourcePath).getSize();
        auto f = File(sourcePath, "rb");
        addStream(archiveName, (scope sink) {
            ubyte[8192] buf;
            while (true) {
                auto got = f.rawRead(buf[]);
                if (got.length == 0) break;
                sink(got);
            }
        }, fileSize);
        return this;
    }

    /// Add directory tree recursively.
    ref Self addTree(in Path rootPath, string prefix = null,
                     FollowSymlinks followSym = FollowSymlinks.yes) return {
        return addTree(rootPath.toString(), prefix, followSym);
    }

    /// ditto
    ref Self addTree(string rootPath, string prefix = null,
                     FollowSymlinks followSym = FollowSymlinks.yes) return {
        auto root = Path(rootPath).toAbsolute();
        if (prefix is null) prefix = root.baseName;
        foreach (de; root.walkDepth(followSym == FollowSymlinks.yes)) {
            auto relPath = de.relativeTo(root);
            auto archName = prefix ~ "/" ~ relPath;
            version(Posix) {
                if (de.isSymlink) {
                    if (followSym == FollowSymlinks.no) {
                        addSymlink(archName, de.readLink.toString());
                    } else {
                        if (de.isDir) addDirectory(archName);
                        else          add(de.toString(), archName);
                    }
                    continue;
                }
            } else {
                if (followSym == FollowSymlinks.no)
                    throw new DarkArchiveException(
                        "FollowSymlinks.no is not supported on this platform");
            }
            if (de.isDir)       addDirectory(archName);
            else if (de.isFile) add(de.toString(), archName);
        }
        return this;
    }

    /// Add from in-memory buffer.
    ref Self addBuffer(string archiveName, const(ubyte)[] data,
                       uint permissions = octal!644) return {
        _writer.addBuffer(archiveName, data, permissions);
        return this;
    }

    /// Add empty directory.
    ref Self addDirectory(string archiveName,
                          uint permissions = octal!755) return {
        _writer.addDirectory(archiveName, permissions);
        return this;
    }

    /// Add from streaming source.
    ref Self addStream(string archiveName,
                       scope void delegate(scope void delegate(const(ubyte)[])) reader,
                       long size = -1,
                       uint permissions = octal!644) return {
        _writer.addStream(archiveName, reader, size, permissions);
        return this;
    }

    /// Add symlink entry.
    ref Self addSymlink(string archiveName, string target) return {
        _writer.addSymlink(archiveName, target);
        return this;
    }

    /// Flush and finalise the archive.  Must be called explicitly for
    /// sink-backed writers; file-backed writers also call it in the destructor.
    void finish() {
        if (_finished) return;
        _finished = true;
        _writer.finish();
    }

    ~this() {
        if (_finished || _writer is null) return;
        // Auto-finish: always for file-backed (prevents truncated files on early
        // return); for sink-backed only when _filePath is non-null (never, so
        // sink-backed writers require an explicit finish() call).
        if (_filePath !is null)
            try { finish(); } catch (Exception) {}
    }
}


// ===========================================================================
// Unit tests
// ===========================================================================

version(unittest) {

    private immutable testDataDir = "test-data";

    // Local aliases for brevity
    private alias RZip   = DarkArchiveReader!(DarkArchiveFormat.zip);
    private alias RTar   = DarkArchiveReader!(DarkArchiveFormat.tar);
    private alias RTarGz = DarkArchiveReader!(DarkArchiveFormat.tarGz);
    private alias WZip   = DarkArchiveWriter!(DarkArchiveFormat.zip);
    private alias WTar   = DarkArchiveWriter!(DarkArchiveFormat.tar);
    private alias WTarGz = DarkArchiveWriter!(DarkArchiveFormat.tarGz);

    // -------------------------------------------------------------------
    // probeArchive
    // -------------------------------------------------------------------

    @("probeArchive: detects ZIP from file")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        probeArchive(testDataDir ~ "/test-zip.zip").shouldEqual(DarkArchiveFormat.zip);
    }

    @("probeArchive: detects TAR.GZ from file")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        probeArchive(testDataDir ~ "/test.tar.gz").shouldEqual(DarkArchiveFormat.tarGz);
    }

    @("probeArchive: detects plain TAR from file")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        probeArchive(testDataDir ~ "/test-symlink.tar").shouldEqual(DarkArchiveFormat.tar);
    }

    @("probeArchive: detects format from header bytes")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        probeArchive(cast(const(ubyte)[]) "PK\x03\x04extradata")
            .shouldEqual(DarkArchiveFormat.zip);
        probeArchive(cast(const(ubyte)[]) "\x1f\x8b\x08\x00extradata")
            .shouldEqual(DarkArchiveFormat.tarGz);
        ubyte[264] tarHeader;
        tarHeader[257 .. 262] = cast(ubyte[5]) "ustar";
        probeArchive(tarHeader[]).shouldEqual(DarkArchiveFormat.tar);
    }

    @("probeArchive: throws on unknown format")
    unittest {
        import unit_threaded.assertions : shouldThrow;
        shouldThrow!DarkArchiveException(
            probeArchive(cast(const(ubyte)[]) "????garbage"));
    }

    @("probeArchive: throws when header too small")
    unittest {
        import unit_threaded.assertions : shouldThrow;
        shouldThrow!DarkArchiveException(
            probeArchive(cast(const(ubyte)[]) "PK"));
    }

    // -------------------------------------------------------------------
    // Cross-format behaviour
    // -------------------------------------------------------------------

    @("cross-format: tarReader on a ZIP file yields zero entries")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        import darkarchive.formats.tar.reader : tarReader;
        // ZIP magic bytes fail the TAR checksum check on the first block.
        auto reader = tarReader(testDataDir ~ "/test-zip.zip");
        scope(exit) reader.close();
        int count;
        foreach (entry; reader.entries) count++;
        count.shouldEqual(0);
    }

    @("cross-format: DarkArchiveReader!tar on a ZIP file yields zero entries")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        auto reader = RTar(testDataDir ~ "/test-zip.zip");
        scope(exit) reader.close();
        size_t count;
        reader.processEntries((scope ref item) { count++; });
        count.shouldEqual(0);
    }

    @("cross-format: DarkArchiveReader!zip on a TAR file throws")
    unittest {
        import unit_threaded.assertions : shouldThrow;
        // ZIP reader parses the central directory; a plain TAR file has no ZIP
        // magic bytes and must be rejected with a DarkArchiveException.
        shouldThrow!DarkArchiveException(
            RZip(testDataDir ~ "/test-symlink.tar"));
    }

    // -------------------------------------------------------------------
    // ArchiveCapability / supports()
    // -------------------------------------------------------------------

    @("capability: ZIP supports randomAccessRead only")
    unittest {
        import unit_threaded.assertions : shouldBeTrue, shouldBeFalse;
        supports(DarkArchiveFormat.zip, ArchiveCapability.randomAccessRead).shouldBeTrue;
        supports(DarkArchiveFormat.zip, ArchiveCapability.streamingRead).shouldBeFalse;
        supports(DarkArchiveFormat.zip, ArchiveCapability.streamingWrite).shouldBeFalse;
    }

    @("capability: TAR supports streaming read and write")
    unittest {
        import unit_threaded.assertions : shouldBeTrue, shouldBeFalse;
        supports(DarkArchiveFormat.tar, ArchiveCapability.streamingRead).shouldBeTrue;
        supports(DarkArchiveFormat.tar, ArchiveCapability.streamingWrite).shouldBeTrue;
        supports(DarkArchiveFormat.tar, ArchiveCapability.randomAccessRead).shouldBeFalse;
    }

    @("capability: TAR.GZ supports streaming read and write")
    unittest {
        import unit_threaded.assertions : shouldBeTrue, shouldBeFalse;
        supports(DarkArchiveFormat.tarGz, ArchiveCapability.streamingRead).shouldBeTrue;
        supports(DarkArchiveFormat.tarGz, ArchiveCapability.streamingWrite).shouldBeTrue;
        supports(DarkArchiveFormat.tarGz, ArchiveCapability.randomAccessRead).shouldBeFalse;
    }

    @("capability: format enum constant feeds supports() naturally")
    unittest {
        import unit_threaded.assertions : shouldBeTrue, shouldBeFalse;
        RZip.format.supports(ArchiveCapability.randomAccessRead).shouldBeTrue;
        RZip.format.supports(ArchiveCapability.streamingRead).shouldBeFalse;
    }

    @("capability: ZIP not usable with darkArchiveReader/Writer at compile time")
    unittest {
        import darkarchive.datasource : ByteChunks, DelegateSink;
        // darkArchiveReader/Writer require fmt != zip (template constraint)
        static assert(!__traits(compiles,
            darkArchiveReader!(DarkArchiveFormat.zip)(ByteChunks.init)));
        static assert(!__traits(compiles,
            darkArchiveWriter!(DarkArchiveFormat.zip)(DelegateSink.init)));
        // TAR and TARGZ are supported
        static assert(__traits(compiles,
            darkArchiveReader!(DarkArchiveFormat.tar)(ByteChunks.init)));
        static assert(__traits(compiles,
            darkArchiveWriter!(DarkArchiveFormat.tar)(DelegateSink.init)));
    }

    // -------------------------------------------------------------------
    // High-level read
    // -------------------------------------------------------------------

    @("high-level: read zip and verify content")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        auto reader = RZip(Path(testDataDir, "test-zip.zip"));
        scope(exit) reader.close();
        string[] names;
        foreach (ref item; reader.entries) {
            names ~= item.meta.pathname;
            if (item.meta.pathname == "file1.txt")
                item.data.readText().shouldEqual("Hello from file1\n");
        }
        assert(names.length > 0);
    }

    @("high-level: read tar.gz and verify content")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        auto reader = RTarGz(Path(testDataDir, "test.tar.gz"));
        scope(exit) reader.close();
        foreach (ref item; reader.entries) {
            if (item.meta.pathname == "./file1.txt")
                item.data.readText().shouldEqual("Hello from file1\n");
        }
    }

    // -------------------------------------------------------------------
    // High-level write round-trips
    // -------------------------------------------------------------------

    @("high-level: write zip round-trip")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue;
        auto outPath = Path(testDataDir, "test-hl-write.zip");
        WZip(outPath)
            .addBuffer("hello.txt", cast(const(ubyte)[]) "Hello World!")
            .addDirectory("emptydir")
            .finish();
        auto reader = RZip(outPath);
        scope(exit) {
            reader.close();
            if (outPath.exists) outPath.remove();
        }
        bool foundHello;
        foreach (ref item; reader.entries) {
            if (item.meta.pathname == "hello.txt") {
                foundHello = true;
                item.data.readText().shouldEqual("Hello World!");
            }
        }
        foundHello.shouldBeTrue;
    }

    @("high-level: write tar.gz round-trip")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        auto outPath = Path(testDataDir, "test-hl-write.tar.gz");
        WTarGz(outPath)
            .addBuffer("file-a.txt", cast(const(ubyte)[]) "Content A")
            .addBuffer("file-b.txt", cast(const(ubyte)[]) "Content B")
            .finish();
        auto reader = RTarGz(outPath);
        scope(exit) {
            reader.close();
            if (outPath.exists) outPath.remove();
        }
        int count;
        foreach (ref item; reader.entries) {
            count++;
            if (item.meta.pathname == "file-a.txt")
                item.data.readText().shouldEqual("Content A");
            else if (item.meta.pathname == "file-b.txt")
                item.data.readText().shouldEqual("Content B");
        }
        count.shouldEqual(2);
    }

    @("high-level: cross-format round-trip")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        auto zipPath = Path(testDataDir, "test-hl-cross.zip");
        auto tarPath = Path(testDataDir, "test-hl-cross.tar.gz");
        scope(exit) {
            if (zipPath.exists) zipPath.remove();
            if (tarPath.exists) tarPath.remove();
        }
        auto content = cast(const(ubyte)[]) "Cross-format test";
        WZip(zipPath).addBuffer("cross.txt", content).finish();
        WTarGz(tarPath).addBuffer("cross.txt", content).finish();

        auto r1 = RZip(zipPath);
        scope(exit) r1.close();
        foreach (ref item; r1.entries) {
            if (item.meta.pathname == "cross.txt")
                item.data.readText().shouldEqual("Cross-format test");
        }

        auto r2 = RTarGz(tarPath);
        scope(exit) r2.close();
        foreach (ref item; r2.entries) {
            if (item.meta.pathname == "cross.txt")
                item.data.readText().shouldEqual("Cross-format test");
        }
    }

    @("high-level: non-existent file throws")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;
        bool caught;
        try { auto reader = RZip(Path("nonexistent-file.zip")); }
        catch (Exception) { caught = true; }
        caught.shouldBeTrue;
    }

    @("high-level: extractTo")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        auto extractDir = Path(testDataDir, "extract-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RZip(Path(testDataDir, "test-zip.zip"));
        scope(exit) reader.close();
        reader.extractTo(extractDir);
        assert((extractDir ~ "file1.txt").exists);
        (extractDir ~ "file1.txt").readFileText().shouldEqual("Hello from file1\n");
        assert((extractDir ~ "subdir/nested.txt").exists);
        (extractDir ~ "subdir/nested.txt").readFileText().shouldEqual("Nested file content\n");
    }

    @("high-level: write to file, read back")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        auto tmpPath = "test-data/test-hl-mem.zip";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WZip(tmpPath)
            .addBuffer("mem.txt", cast(const(ubyte)[]) "from memory")
            .finish();
        auto reader = RZip(tmpPath);
        scope(exit) reader.close();
        foreach (ref item; reader.entries) {
            if (item.meta.pathname == "mem.txt")
                item.data.readText().shouldEqual("from memory");
        }
    }

    @("high-level: method chaining")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        auto tmpPath = "test-data/test-hl-chain.zip";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WZip(tmpPath)
            .addBuffer("a.txt", cast(const(ubyte)[]) "A")
            .addBuffer("b.txt", cast(const(ubyte)[]) "B")
            .addBuffer("c.txt", cast(const(ubyte)[]) "C")
            .finish();
        auto reader = RZip(tmpPath);
        scope(exit) reader.close();
        int count;
        foreach (ref item; reader.entries) { count++; }
        count.shouldEqual(3);
    }

    // -------------------------------------------------------------------
    // Security tests — extraction
    // -------------------------------------------------------------------

    @("security: extractTo rejects path with '..' components")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;
        auto tmpPath = "test-data/test-sec-dotdot.zip";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WZip(tmpPath).addBuffer("../escape.txt", cast(const(ubyte)[]) "escaped!").finish();
        auto extractDir = Path(testDataDir, "sec-dotdot-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RZip(tmpPath);
        scope(exit) reader.close();
        bool caught;
        try { reader.extractTo(extractDir); }
        catch (DarkArchiveException) { caught = true; }
        caught.shouldBeTrue;
        assert(!Path(testDataDir, "escape.txt").exists);
    }

    @("security: extractTo rejects nested '..' traversal")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;
        auto tmpPath = "test-data/test-sec-nested-dotdot.zip";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WZip(tmpPath).addBuffer("foo/../../escape2.txt", cast(const(ubyte)[]) "escaped!").finish();
        auto extractDir = Path(testDataDir, "sec-nested-dotdot-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RZip(tmpPath);
        scope(exit) reader.close();
        bool caught;
        try { reader.extractTo(extractDir); }
        catch (DarkArchiveException) { caught = true; }
        caught.shouldBeTrue;
    }

    @("security: extractTo rejects absolute paths")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;
        auto tmpPath = "test-data/test-sec-abs.zip";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WZip(tmpPath).addBuffer("/tmp/evil.txt", cast(const(ubyte)[]) "evil!").finish();
        auto extractDir = Path(testDataDir, "sec-abs-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RZip(tmpPath);
        scope(exit) reader.close();
        bool caught;
        try { reader.extractTo(extractDir); }
        catch (DarkArchiveException) { caught = true; }
        caught.shouldBeTrue;
    }

    @("security: extractTo skips symlink with absolute target by default")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;
        import darkarchive.formats.tar.writer : tarWriter;
        auto tmpTar = "test-data/test-sec-symlink-abs.tar";
        scope(exit) if (Path(tmpTar).exists) Path(tmpTar).remove();
        auto tw = tarWriter(tmpTar);
        scope(exit) tw.close();
        tw.addSymlink("evil-link", "/etc/passwd");
        tw.finish();
        auto extractDir = Path(testDataDir, "sec-symlink-abs-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RTar(tmpTar);
        scope(exit) reader.close();
        reader.extractTo(extractDir);
        assert(!(extractDir ~ "evil-link").exists);
    }

    version(Posix) @("security: extractTo rejects absolute symlink when symlinks enabled")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;
        import darkarchive.formats.tar.writer : tarWriter;
        auto tmpTar = "test-data/test-sec-symlink-abs-en.tar";
        scope(exit) if (Path(tmpTar).exists) Path(tmpTar).remove();
        auto tw = tarWriter(tmpTar);
        scope(exit) tw.close();
        tw.addSymlink("evil-link", "/etc/passwd");
        tw.finish();
        auto extractDir = Path(testDataDir, "sec-symlink-abs-enabled-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RTar(tmpTar);
        scope(exit) reader.close();
        bool caught;
        try { reader.extractTo(extractDir, DarkExtractFlags.defaults | DarkExtractFlags.symlinks); }
        catch (DarkArchiveException) { caught = true; }
        caught.shouldBeTrue;
    }

    @("security: extractTo skips symlink with traversal target by default")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;
        import darkarchive.formats.tar.writer : tarWriter;
        auto tmpTar = "test-data/test-sec-symlink-trav.tar";
        scope(exit) if (Path(tmpTar).exists) Path(tmpTar).remove();
        auto tw = tarWriter(tmpTar);
        scope(exit) tw.close();
        tw.addSymlink("escape-link", "../../../../etc/shadow");
        tw.finish();
        auto extractDir = Path(testDataDir, "sec-symlink-trav-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RTar(tmpTar);
        scope(exit) reader.close();
        reader.extractTo(extractDir);
        assert(!(extractDir ~ "escape-link").exists);
    }

    version(Posix) @("security: extractTo rejects traversal symlink when symlinks enabled")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;
        import darkarchive.formats.tar.writer : tarWriter;
        auto tmpTar = "test-data/test-sec-symlink-trav-en.tar";
        scope(exit) if (Path(tmpTar).exists) Path(tmpTar).remove();
        auto tw = tarWriter(tmpTar);
        scope(exit) tw.close();
        tw.addSymlink("escape-link", "../../../../etc/shadow");
        tw.finish();
        auto extractDir = Path(testDataDir, "sec-symlink-trav-enabled-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RTar(tmpTar);
        scope(exit) reader.close();
        bool caught;
        try { reader.extractTo(extractDir, DarkExtractFlags.defaults | DarkExtractFlags.symlinks); }
        catch (DarkArchiveException) { caught = true; }
        caught.shouldBeTrue;
    }

    @("security: extractTo rejects entry named '..'")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;
        auto tmpPath = "test-data/test-sec-dotdot-name.zip";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WZip(tmpPath).addBuffer("..", cast(const(ubyte)[]) "dot dot").finish();
        auto extractDir = Path(testDataDir, "sec-dotdot-name-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RZip(tmpPath);
        scope(exit) reader.close();
        bool caught;
        try { reader.extractTo(extractDir); }
        catch (DarkArchiveException) { caught = true; }
        caught.shouldBeTrue;
    }

    // -------------------------------------------------------------------
    // CVE-inspired tests
    // -------------------------------------------------------------------

    @("CVE: two-step symlink+file — safe by default (symlinks skipped)")
    unittest {
        import darkarchive.formats.tar.writer : tarWriter;
        auto tmpTar = "test-data/test-cve-twostep.tar";
        scope(exit) if (Path(tmpTar).exists) Path(tmpTar).remove();
        auto tw = tarWriter(tmpTar);
        scope(exit) tw.close();
        tw.addSymlink("escape-dir", "/tmp");
        tw.addBuffer("escape-dir/pwned.txt", cast(const(ubyte)[]) "pwned!");
        tw.finish();
        auto extractDir = Path(testDataDir, "sec-twostep-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RTar(tmpTar);
        scope(exit) reader.close();
        reader.extractTo(extractDir);
        assert(!Path("/tmp/pwned.txt").exists);
    }

    version(Posix) @("CVE: two-step symlink+file — absolute target rejected with symlinks enabled")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;
        import darkarchive.formats.tar.writer : tarWriter;
        auto tmpTar = "test-data/test-cve-twostep-en.tar";
        scope(exit) if (Path(tmpTar).exists) Path(tmpTar).remove();
        auto tw = tarWriter(tmpTar);
        scope(exit) tw.close();
        tw.addSymlink("escape-dir", "/tmp");
        tw.addBuffer("escape-dir/pwned.txt", cast(const(ubyte)[]) "pwned!");
        tw.finish();
        auto extractDir = Path(testDataDir, "sec-twostep-enabled-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RTar(tmpTar);
        scope(exit) reader.close();
        bool caught;
        try { reader.extractTo(extractDir, DarkExtractFlags.defaults | DarkExtractFlags.symlinks); }
        catch (DarkArchiveException) { caught = true; }
        caught.shouldBeTrue;
        assert(!Path("/tmp/pwned.txt").exists);
    }

    @("CVE: two-step relative symlink — safe by default (symlinks skipped)")
    unittest {
        import darkarchive.formats.tar.writer : tarWriter;
        auto tmpTar = "test-data/test-cve-twostep-rel.tar";
        scope(exit) if (Path(tmpTar).exists) Path(tmpTar).remove();
        auto tw = tarWriter(tmpTar);
        scope(exit) tw.close();
        tw.addSymlink("linkdir", "../../");
        tw.addBuffer("linkdir/escape.txt", cast(const(ubyte)[]) "escaped!");
        tw.finish();
        auto extractDir = Path(testDataDir, "sec-twostep-rel-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RTar(tmpTar);
        scope(exit) reader.close();
        reader.extractTo(extractDir);
        assert(!Path(testDataDir, "escape.txt").exists);
    }

    version(Posix) @("CVE: two-step relative symlink — rejected with symlinks enabled")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;
        import darkarchive.formats.tar.writer : tarWriter;
        auto tmpTar = "test-data/test-cve-twostep-rel-en.tar";
        scope(exit) if (Path(tmpTar).exists) Path(tmpTar).remove();
        auto tw = tarWriter(tmpTar);
        scope(exit) tw.close();
        tw.addSymlink("linkdir", "../../");
        tw.addBuffer("linkdir/escape.txt", cast(const(ubyte)[]) "escaped!");
        tw.finish();
        auto extractDir = Path(testDataDir, "sec-twostep-rel-en-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RTar(tmpTar);
        scope(exit) reader.close();
        bool caught;
        try { reader.extractTo(extractDir, DarkExtractFlags.defaults | DarkExtractFlags.symlinks); }
        catch (DarkArchiveException) { caught = true; }
        caught.shouldBeTrue;
    }

    @("CVE: Zip Slip - file..name.txt is legitimate, not rejected")
    unittest {
        auto tmpPath = "test-data/test-cve-legit-dotdot.zip";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WZip(tmpPath).addBuffer("file..name.txt", cast(const(ubyte)[]) "legitimate").finish();
        auto extractDir = Path(testDataDir, "sec-legit-dotdot-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RZip(tmpPath);
        scope(exit) reader.close();
        reader.extractTo(extractDir);
        assert((extractDir ~ "file..name.txt").exists);
    }

    @("CVE: pax path override with traversal")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;
        import darkarchive.formats.tar.writer : tarWriter;
        auto tmpTar = "test-data/test-cve-pax-trav.tar";
        scope(exit) if (Path(tmpTar).exists) Path(tmpTar).remove();
        auto tw = tarWriter(tmpTar);
        scope(exit) tw.close();
        tw.addBuffer("../../pax-evil.txt", cast(const(ubyte)[]) "pax attack");
        tw.finish();
        auto extractDir = Path(testDataDir, "sec-pax-trav-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RTar(tmpTar);
        scope(exit) reader.close();
        bool caught;
        try { reader.extractTo(extractDir); }
        catch (DarkArchiveException) { caught = true; }
        caught.shouldBeTrue;
    }

    @("security: absolute symlink skipped with DarkExtractFlags.none")
    unittest {
        import darkarchive.formats.tar.writer : tarWriter;
        auto tmpTar = "test-data/test-sec-abs-sym-uncond.tar";
        scope(exit) if (Path(tmpTar).exists) Path(tmpTar).remove();
        auto tw = tarWriter(tmpTar);
        scope(exit) tw.close();
        tw.addSymlink("danger", "/etc/passwd");
        tw.finish();
        auto extractDir = Path(testDataDir, "sec-abs-sym-unconditional");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RTar(tmpTar);
        scope(exit) reader.close();
        reader.extractTo(extractDir, DarkExtractFlags.none);
        assert(!(extractDir ~ "danger").exists);
    }

    version(Posix) @("security: absolute symlink rejected unconditionally with symlinks flag")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;
        import darkarchive.formats.tar.writer : tarWriter;
        auto tmpTar = "test-data/test-sec-abs-sym-flag.tar";
        scope(exit) if (Path(tmpTar).exists) Path(tmpTar).remove();
        auto tw = tarWriter(tmpTar);
        scope(exit) tw.close();
        tw.addSymlink("danger", "/etc/passwd");
        tw.finish();
        auto extractDir = Path(testDataDir, "sec-abs-sym-flag-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RTar(tmpTar);
        scope(exit) reader.close();
        bool caught;
        try { reader.extractTo(extractDir, DarkExtractFlags.symlinks); }
        catch (DarkArchiveException) { caught = true; }
        caught.shouldBeTrue;
    }

    // -------------------------------------------------------------------
    // Symlink opt-in tests
    // -------------------------------------------------------------------

    @("security: symlinks skipped by default during extraction")
    unittest {
        import darkarchive.formats.tar.writer : tarWriter;
        auto tmpTar = "test-data/test-sec-sym-skip.tar";
        scope(exit) if (Path(tmpTar).exists) Path(tmpTar).remove();
        auto tw = tarWriter(tmpTar);
        scope(exit) tw.close();
        tw.addBuffer("real-file.txt", cast(const(ubyte)[]) "I exist");
        tw.addSymlink("safe-link", "real-file.txt");
        tw.finish();
        auto extractDir = Path(testDataDir, "sec-sym-skip-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RTar(tmpTar);
        scope(exit) reader.close();
        reader.extractTo(extractDir);
        assert((extractDir ~ "real-file.txt").exists);
        assert(!(extractDir ~ "safe-link").exists);
    }

    version(Posix) @("security: symlinks created when flag is set")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        import darkarchive.formats.tar.writer : tarWriter;
        auto tmpTar = "test-data/test-sec-sym-create.tar";
        scope(exit) if (Path(tmpTar).exists) Path(tmpTar).remove();
        auto tw = tarWriter(tmpTar);
        scope(exit) tw.close();
        tw.addBuffer("target.txt", cast(const(ubyte)[]) "target content");
        tw.addSymlink("link.txt", "target.txt");
        tw.finish();
        auto extractDir = Path(testDataDir, "sec-sym-create-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RTar(tmpTar);
        scope(exit) reader.close();
        reader.extractTo(extractDir, DarkExtractFlags.defaults | DarkExtractFlags.symlinks);
        assert((extractDir ~ "target.txt").exists);
        assert((extractDir ~ "link.txt").exists);
        assert((extractDir ~ "link.txt").isSymlink());
        (extractDir ~ "link.txt").readFileText().shouldEqual("target content");
    }

    version(Posix) @("security: absolute symlink still rejected even with symlinks flag")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;
        import darkarchive.formats.tar.writer : tarWriter;
        auto tmpTar = "test-data/test-sec-sym-abs-flag.tar";
        scope(exit) if (Path(tmpTar).exists) Path(tmpTar).remove();
        auto tw = tarWriter(tmpTar);
        scope(exit) tw.close();
        tw.addSymlink("evil", "/etc/passwd");
        tw.finish();
        auto extractDir = Path(testDataDir, "sec-sym-abs-flag-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RTar(tmpTar);
        scope(exit) reader.close();
        bool caught;
        try { reader.extractTo(extractDir, DarkExtractFlags.defaults | DarkExtractFlags.symlinks); }
        catch (DarkArchiveException) { caught = true; }
        caught.shouldBeTrue;
    }

    // -------------------------------------------------------------------
    // Chained-symlink bypass test
    // -------------------------------------------------------------------

    version(Posix)
    @("security: chained symlink escaping extractDir is blocked by resolveRealPath")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;
        import darkarchive.formats.tar.writer : tarWriter;

        // extractDir/link2 is a PRE-EXISTING symlink pointing OUTSIDE extractDir.
        // The archive then adds link1 → link2 (safe-looking one hop), plus a file
        // under link1/.  The resolved chain is link1→link2→outside.
        auto extractDir = Path(testDataDir, "sec-chained-sym-extract");
        auto outsideDir = Path(testDataDir, "sec-chained-sym-outside");
        scope(exit) {
            if (extractDir.exists) extractDir.remove();
            if (outsideDir.exists) outsideDir.remove();
        }
        extractDir.mkdir();
        outsideDir.mkdir();
        // Inside extractDir: link2 → ../sec-chained-sym-outside (outside)
        Path("../sec-chained-sym-outside").symlink(extractDir ~ "link2");

        auto tmpTar = "test-data/test-sec-chained-sym.tar";
        scope(exit) if (Path(tmpTar).exists) Path(tmpTar).remove();
        auto tw = tarWriter(tmpTar);
        scope(exit) tw.close();
        tw.addSymlink("link1", "link2");                               // one-hop, looks safe
        tw.addBuffer("link1/evil.txt", cast(const(ubyte)[]) "escaped!");
        tw.finish();

        auto reader = RTar(tmpTar);
        scope(exit) reader.close();
        bool caught;
        try {
            reader.extractTo(extractDir,
                DarkExtractFlags.defaults | DarkExtractFlags.symlinks);
        } catch (DarkArchiveException) { caught = true; }

        caught.shouldBeTrue;
        assert(!(outsideDir ~ "evil.txt").exists,
            "evil.txt must not escape to the outside directory via chained symlinks");
    }

    // -------------------------------------------------------------------
    // Hardlink extraction tests
    // -------------------------------------------------------------------

    version(Posix) @("hardlink: extractTo creates hardlink when symlinks flag set")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue;
        import darkarchive.formats.tar.writer : tarWriter;
        import core.sys.posix.sys.stat : stat_t, stat;

        auto tmpTar = "test-data/test-hardlink-extract.tar";
        scope(exit) if (Path(tmpTar).exists) Path(tmpTar).remove();
        auto tw = tarWriter(tmpTar);
        scope(exit) tw.close();
        tw.addBuffer("original.txt", cast(const(ubyte)[]) "hardlink content");
        tw.addHardlink("link.txt", "original.txt");
        tw.finish();

        auto extractDir = Path(testDataDir, "hardlink-extract-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RTar(tmpTar);
        scope(exit) reader.close();
        reader.extractTo(extractDir, DarkExtractFlags.symlinks);

        assert((extractDir ~ "original.txt").exists);
        assert((extractDir ~ "link.txt").exists);
        (extractDir ~ "link.txt").readFileText().shouldEqual("hardlink content");

        // Verify same inode — confirms it's a real hardlink, not a copy
        stat_t s1, s2;
        stat((extractDir ~ "original.txt").toString.ptr, &s1);
        stat((extractDir ~ "link.txt").toString.ptr, &s2);
        (s1.st_ino == s2.st_ino).shouldBeTrue;
    }

    @("hardlink: skipped by default when symlinks flag not set")
    unittest {
        import unit_threaded.assertions : shouldBeFalse;
        import darkarchive.formats.tar.writer : tarWriter;

        auto tmpTar = "test-data/test-hardlink-skip.tar";
        scope(exit) if (Path(tmpTar).exists) Path(tmpTar).remove();
        auto tw = tarWriter(tmpTar);
        scope(exit) tw.close();
        tw.addBuffer("original.txt", cast(const(ubyte)[]) "content");
        tw.addHardlink("link.txt", "original.txt");
        tw.finish();

        auto extractDir = Path(testDataDir, "hardlink-skip-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RTar(tmpTar);
        scope(exit) reader.close();
        reader.extractTo(extractDir); // default flags — symlinks flag not set

        assert((extractDir ~ "original.txt").exists);
        (extractDir ~ "link.txt").exists.shouldBeFalse;
    }

    @("hardlink: absolute target throws")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;
        import darkarchive.formats.tar.writer : tarWriter;

        auto tmpTar = "test-data/test-hardlink-abs.tar";
        scope(exit) if (Path(tmpTar).exists) Path(tmpTar).remove();
        auto tw = tarWriter(tmpTar);
        scope(exit) tw.close();
        tw.addHardlink("link.txt", "/etc/passwd");
        tw.finish();

        auto extractDir = Path(testDataDir, "hardlink-abs-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RTar(tmpTar);
        scope(exit) reader.close();
        bool caught;
        try { reader.extractTo(extractDir, DarkExtractFlags.symlinks); }
        catch (DarkArchiveException) { caught = true; }
        caught.shouldBeTrue;
    }

    version(Posix) {} else
    @("hardlink: non-Posix platform throws DarkArchiveException when symlinks flag is set")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;
        import darkarchive.formats.tar.writer : tarWriter;

        auto tmpTar = "test-data/test-hardlink-nonposix.tar";
        scope(exit) if (Path(tmpTar).exists) Path(tmpTar).remove();
        auto tw = tarWriter(tmpTar);
        scope(exit) tw.close();
        tw.addBuffer("original.txt", cast(const(ubyte)[]) "content");
        tw.addHardlink("link.txt", "original.txt");
        tw.finish();

        auto extractDir = Path(testDataDir, "hardlink-nonposix-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RTar(tmpTar);
        scope(exit) reader.close();
        bool caught;
        // With symlinks flag: on non-Posix, hardlink extraction must throw
        // rather than silently dropping the entry (same behaviour as symlinks).
        try { reader.extractTo(extractDir, DarkExtractFlags.symlinks); }
        catch (DarkArchiveException) { caught = true; }
        caught.shouldBeTrue;
    }

    @("hardlink: traversal target throws")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;
        import darkarchive.formats.tar.writer : tarWriter;

        auto tmpTar = "test-data/test-hardlink-traversal.tar";
        scope(exit) if (Path(tmpTar).exists) Path(tmpTar).remove();
        auto tw = tarWriter(tmpTar);
        scope(exit) tw.close();
        tw.addHardlink("link.txt", "../outside.txt");
        tw.finish();

        auto extractDir = Path(testDataDir, "hardlink-traversal-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RTar(tmpTar);
        scope(exit) reader.close();
        bool caught;
        try { reader.extractTo(extractDir, DarkExtractFlags.defaults | DarkExtractFlags.symlinks); }
        catch (DarkArchiveException) { caught = true; }
        caught.shouldBeTrue;
    }

    // -------------------------------------------------------------------
    // ExtractionLimits tests
    // -------------------------------------------------------------------

    @("limits: maxEntries throws when exceeded")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;

        auto tmpPath = "test-data/test-limits-entries.zip";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WZip(tmpPath)
            .addBuffer("a.txt", cast(const(ubyte)[]) "A")
            .addBuffer("b.txt", cast(const(ubyte)[]) "B")
            .addBuffer("c.txt", cast(const(ubyte)[]) "C")
            .finish();

        auto extractDir = Path(testDataDir, "limits-entries-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RZip(tmpPath);
        scope(exit) reader.close();
        bool caught;
        try { reader.extractTo(extractDir, DarkExtractFlags.defaults,
                               ExtractionLimits(ulong.max, ulong.max, 2)); }
        catch (DarkArchiveException) { caught = true; }
        caught.shouldBeTrue;
    }

    @("limits: maxEntryBytes throws when exceeded")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;

        auto tmpPath = "test-data/test-limits-entrybytes.zip";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WZip(tmpPath)
            .addBuffer("big.bin", new ubyte[](1024))
            .finish();

        auto extractDir = Path(testDataDir, "limits-entrybytes-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RZip(tmpPath);
        scope(exit) reader.close();
        bool caught;
        try { reader.extractTo(extractDir, DarkExtractFlags.defaults,
                               ExtractionLimits(ulong.max, 512, ulong.max)); }
        catch (DarkArchiveException) { caught = true; }
        caught.shouldBeTrue;
    }

    @("limits: maxTotalBytes throws when exceeded")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;

        auto tmpPath = "test-data/test-limits-totalbytes.zip";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WZip(tmpPath)
            .addBuffer("a.bin", new ubyte[](512))
            .addBuffer("b.bin", new ubyte[](512))
            .finish();

        auto extractDir = Path(testDataDir, "limits-totalbytes-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RZip(tmpPath);
        scope(exit) reader.close();
        bool caught;
        try { reader.extractTo(extractDir, DarkExtractFlags.defaults,
                               ExtractionLimits(768, ulong.max, ulong.max)); }
        catch (DarkArchiveException) { caught = true; }
        caught.shouldBeTrue;
    }

    // -------------------------------------------------------------------
    // ExtractionLimits tests — TAR
    // -------------------------------------------------------------------

    @("limits: TAR maxEntries throws when exceeded")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;

        auto tmpPath = "test-data/test-limits-tar-entries.tar";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WTar(tmpPath)
            .addBuffer("a.txt", cast(const(ubyte)[]) "A")
            .addBuffer("b.txt", cast(const(ubyte)[]) "B")
            .addBuffer("c.txt", cast(const(ubyte)[]) "C")
            .finish();

        auto extractDir = Path(testDataDir, "limits-tar-entries-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RTar(tmpPath);
        scope(exit) reader.close();
        bool caught;
        try { reader.extractTo(extractDir, DarkExtractFlags.defaults,
                               ExtractionLimits(ulong.max, ulong.max, 2)); }
        catch (DarkArchiveException) { caught = true; }
        caught.shouldBeTrue;
    }

    @("limits: TAR maxEntryBytes throws when exceeded")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;

        auto tmpPath = "test-data/test-limits-tar-entrybytes.tar";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WTar(tmpPath)
            .addBuffer("big.bin", new ubyte[](1024))
            .finish();

        auto extractDir = Path(testDataDir, "limits-tar-entrybytes-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RTar(tmpPath);
        scope(exit) reader.close();
        bool caught;
        try { reader.extractTo(extractDir, DarkExtractFlags.defaults,
                               ExtractionLimits(ulong.max, 512, ulong.max)); }
        catch (DarkArchiveException) { caught = true; }
        caught.shouldBeTrue;
    }

    @("limits: TAR maxTotalBytes throws when exceeded")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;

        auto tmpPath = "test-data/test-limits-tar-totalbytes.tar";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WTar(tmpPath)
            .addBuffer("a.bin", new ubyte[](512))
            .addBuffer("b.bin", new ubyte[](512))
            .finish();

        auto extractDir = Path(testDataDir, "limits-tar-totalbytes-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RTar(tmpPath);
        scope(exit) reader.close();
        bool caught;
        try { reader.extractTo(extractDir, DarkExtractFlags.defaults,
                               ExtractionLimits(768, ulong.max, ulong.max)); }
        catch (DarkArchiveException) { caught = true; }
        caught.shouldBeTrue;
    }

    // -------------------------------------------------------------------
    // Creative attack vector tests
    // -------------------------------------------------------------------

    @("attack: null byte in ZIP filename — archive listable, extraction throws")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;
        auto tmpPath = "test-data/test-atk-null-byte.zip";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WZip(tmpPath).addBuffer("safe.txt\x00hidden", cast(const(ubyte)[]) "trick").finish();

        // Archive can be opened and entries listed — NUL preserved in pathname.
        auto reader = RZip(tmpPath);
        scope(exit) reader.close();
        string foundName;
        foreach (ref item; reader.entries) { foundName = item.meta.pathname; }
        assert(foundName.length > 0 && foundName[8] == '\0',
            "entry.pathname should contain the NUL byte");

        // Extraction must throw — NUL in path is rejected unconditionally.
        auto extractDir = Path(testDataDir, "sec-null-byte-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader2 = RZip(tmpPath);
        scope(exit) reader2.close();
        bool caught;
        try { reader2.extractTo(extractDir); }
        catch (DarkArchiveException) { caught = true; }
        caught.shouldBeTrue;
        assert(!(extractDir ~ "hidden").exists, "hidden must not be written");
    }

    @("attack: NUL in TAR header name field is truncated (fixed-width C-string convention)")
    unittest {
        // Fixed-width TAR header name fields use the C-string convention: NUL is
        // the field terminator.  parseString already stops at NUL — this is
        // correct, not a silent failure.  Variable-length PAX paths that contain
        // NUL are rejected at extraction time (see reader.d unit tests for that).
        import unit_threaded.assertions : shouldEqual;
        import darkarchive.formats.tar.writer : tarWriter;
        import darkarchive.formats.tar.reader : tarReader;
        import std.format : format;

        auto tmpTar = "test-data/test-atk-null-hdr.tar";
        scope(exit) if (Path(tmpTar).exists) Path(tmpTar).remove();
        auto tw = tarWriter(tmpTar);
        scope(exit) tw.close();
        tw.addBuffer("safe.txt", cast(const(ubyte)[]) "content");
        tw.finish();

        // Inject NUL at position 4: "safe.txt" → "safe\0txt", recompute checksum.
        auto data = cast(ubyte[]) Path(tmpTar).readFile();
        assert(data.length >= 512);
        data[4] = 0;
        uint cs = 0;
        foreach (i; 0 .. 512) cs += (i >= 148 && i < 156) ? ' ' : data[i];
        auto csStr = format!"%06o\0 "(cs);
        data[148 .. 156] = cast(ubyte[8]) csStr[0 .. 8];
        Path(tmpTar).writeFile(data);

        auto reader = tarReader(tmpTar);
        scope(exit) reader.close();
        string foundName;
        foreach (entry; reader.entries) { foundName = entry.pathname; reader.skipData(); }
        // parseString stops at NUL → "safe" (C-string convention for fixed-width fields)
        foundName.shouldEqual("safe");
    }

    version(Posix) @("attack: NUL in TAR PAX path — archive listable, extraction throws")
    unittest {
        // PAX paths are variable-length strings; NUL has no defined meaning.
        // The entry can be listed but extraction must throw.
        import unit_threaded.assertions : shouldBeTrue;
        import darkarchive.formats.tar.reader : tarReader;
        import std.format : format;

        // Craft a minimal TAR: PAX header claiming path="evil\0safe", then file.
        // PAX record: "18 path=evil\0safe\n"
        // LENGTH=18: 2 + 1 + "path=evil\0safe\n"(15) = 18 ✓
        immutable ubyte[] paxContent = [
            '1','8',' ','p','a','t','h','=','e','v','i','l',
            0,'s','a','f','e','\n'  // 18 bytes total
        ];
        assert(paxContent.length == 18);

        ubyte[512] paxHdr;  paxHdr[] = 0;
        paxHdr[0..9]    = cast(ubyte[9]) "PaxHeader";
        paxHdr[156]     = 'x';
        paxHdr[257..263] = cast(ubyte[6]) "ustar\0";
        paxHdr[263..265] = cast(ubyte[2]) "00";
        paxHdr[100..108] = cast(ubyte[8]) "0000644\0";
        // size = 18 decimal (the PAX record without the trailing pad)
        paxHdr[124..136] = cast(ubyte[12]) "00000000022\0"; // 18 in octal = 22
        paxHdr[136..148] = cast(ubyte[12]) "00000000000\0";
        uint cs = 0;
        foreach (i; 0..512) cs += (i >= 148 && i < 156) ? ' ' : paxHdr[i];
        auto csStr = format!"%06o\0 "(cs);
        paxHdr[148..156] = cast(ubyte[8]) csStr[0..8];

        ubyte[512] paxDataBlock; paxDataBlock[] = 0;
        paxDataBlock[0..18] = paxContent[];

        ubyte[512] fileHdr; fileHdr[] = 0;
        fileHdr[0..5]    = cast(ubyte[5]) "a.txt";
        fileHdr[156]     = '0';
        fileHdr[257..263] = cast(ubyte[6]) "ustar\0";
        fileHdr[263..265] = cast(ubyte[2]) "00";
        fileHdr[100..108] = cast(ubyte[8]) "0000644\0";
        fileHdr[124..136] = cast(ubyte[12]) "00000000000\0";
        fileHdr[136..148] = cast(ubyte[12]) "00000000000\0";
        cs = 0;
        foreach (i; 0..512) cs += (i >= 148 && i < 156) ? ' ' : fileHdr[i];
        csStr = format!"%06o\0 "(cs);
        fileHdr[148..156] = cast(ubyte[8]) csStr[0..8];

        ubyte[1024] eoar; eoar[] = 0;

        auto tmpTar = "test-data/test-atk-null-pax.tar";
        scope(exit) if (Path(tmpTar).exists) Path(tmpTar).remove();
        ubyte[] archiveData;
        archiveData ~= paxHdr[];
        archiveData ~= paxDataBlock[];
        archiveData ~= fileHdr[];
        archiveData ~= eoar[];
        Path(tmpTar).writeFile(archiveData);

        // Listing works — entry has NUL in its pathname.
        auto reader = tarReader(tmpTar);
        scope(exit) reader.close();
        string foundName;
        foreach (entry; reader.entries) { foundName = entry.pathname; reader.skipData(); }
        assert(foundName.length > 4 && foundName[4] == '\0',
            "pathname should contain the NUL byte from PAX override");

        // Extraction must throw.
        auto extractDir = Path(testDataDir, "sec-null-pax-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader2 = RTar(tmpTar);
        scope(exit) reader2.close();
        bool caught;
        try { reader2.extractTo(extractDir); }
        catch (DarkArchiveException) { caught = true; }
        caught.shouldBeTrue;
    }

    @("attack: filename is just '.'")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        auto tmpPath = "test-data/test-atk-dot-name.zip";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WZip(tmpPath).addBuffer(".", cast(const(ubyte)[]) "overwrite root?").finish();
        auto extractDir = Path(testDataDir, "sec-dot-name-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RZip(tmpPath);
        scope(exit) reader.close();
        try { reader.extractTo(extractDir); } catch (Exception) {}
        auto reader2 = RZip(tmpPath);
        scope(exit) reader2.close();
        int count;
        foreach (ref item; reader2.entries) {
            count++;
            item.meta.pathname.shouldEqual(".");
        }
        count.shouldEqual(1);
    }

    @("attack: duplicate filenames in archive")
    unittest {
        auto extractDir = Path(testDataDir, "sec-dupe-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RZip(Path(testDataDir, "test-duplicate-names.zip"));
        scope(exit) reader.close();
        reader.extractTo(extractDir);
        assert((extractDir ~ "dupe.txt").exists);
        auto content = (extractDir ~ "dupe.txt").readFileText();
        assert(content == "first version\n" || content == "second version\n");
    }

    @("attack: very long pathname")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        import std.array : replicate;
        auto segments = "abcdefghijklmnopqrstuvwxyz01234567890123456789abcd/";
        auto longPath = segments.replicate(20) ~ "file.txt";
        auto tmpPath = "test-data/test-atk-longpath.zip";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WZip(tmpPath).addBuffer(longPath, cast(const(ubyte)[]) "deep").finish();
        auto reader = RZip(tmpPath);
        scope(exit) reader.close();
        string foundName, foundContent;
        reader.processEntries(
            (scope ref item) {
                foundName = item.meta.pathname;
                foundContent = item.data.readText();
            });
        foundName.shouldEqual(longPath);
        foundContent.shouldEqual("deep");
    }

    @("attack: control characters in filename")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        auto tmpPath = "test-data/test-atk-ctrl-char.zip";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WZip(tmpPath)
            .addBuffer("line1\nline2.txt", cast(const(ubyte)[]) "newline name")
            .addBuffer("tab\there.txt", cast(const(ubyte)[]) "tab name")
            .finish();
        auto extractDir = Path(testDataDir, "sec-control-char-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader1 = RZip(tmpPath);
        scope(exit) reader1.close();
        try { reader1.extractTo(extractDir); } catch (Exception) {}
        auto reader2 = RZip(tmpPath);
        scope(exit) reader2.close();
        int count;
        foreach (ref item; reader2.entries) { count++; assert(item.meta.pathname.length > 0); }
        count.shouldEqual(2);
    }

    @("attack: RTL override in filename")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        auto tmpPath = "test-data/test-atk-rtl.zip";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WZip(tmpPath)
            .addBuffer("readme\xE2\x80\xAEtxt.exe", cast(const(ubyte)[]) "spoofed extension")
            .finish();
        auto reader = RZip(tmpPath);
        scope(exit) reader.close();
        int count;
        foreach (ref item; reader.entries) { count++; assert(item.meta.pathname.length > 0); }
        count.shouldEqual(1);
    }

    @("attack: deflate bomb (high compression ratio)")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        import darkarchive.formats.zip.writer : ZipWriter;
        import darkarchive.formats.zip.reader : ZipReader;
        auto zeros = new ubyte[](1024 * 1024);
        auto tmpPath = "test-data/test-atk-bomb.zip";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        auto writer = ZipWriter.createToFile(tmpPath);
        scope(exit) writer.close();
        writer.addBuffer("bomb.bin", zeros);
        writer.finish();
        auto reader = ZipReader(tmpPath);
        scope(exit) reader.close();
        assert(reader.length == 1);
        auto content = reader.readData(0);
        content.length.shouldEqual(1024 * 1024);
        foreach (b; content) assert(b == 0);
    }

    @("attack: overlapping central directory entries")
    unittest {
        import darkarchive.formats.zip.reader : ZipReader;
        auto reader = ZipReader(testDataDir ~ "/test-duplicate-names.zip");
        assert(reader.length >= 2);
        foreach (i; 0 .. reader.length) {
            auto data = reader.readData(i);
            assert(data !is null);
        }
    }

    @("attack: file and directory with same name")
    unittest {
        auto tmpPath = "test-data/test-atk-conflict.zip";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WZip(tmpPath)
            .addDirectory("conflict")
            .addBuffer("conflict", cast(const(ubyte)[]) "file wins?")
            .finish();
        auto extractDir = Path(testDataDir, "sec-conflict-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RZip(tmpPath);
        scope(exit) reader.close();
        try { reader.extractTo(extractDir); } catch (Exception) {}
    }

    @("attack: colon in filename (NTFS ADS)")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        auto tmpPath = "test-data/test-atk-colon.zip";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WZip(tmpPath).addBuffer("file.txt:hidden", cast(const(ubyte)[]) "ADS data").finish();
        auto reader = RZip(tmpPath);
        scope(exit) reader.close();
        int count;
        foreach (ref item; reader.entries) {
            count++;
            assert(item.meta.pathname == "file.txt:hidden");
        }
        count.shouldEqual(1);
    }

    // -------------------------------------------------------------------
    // processEntries tests
    // -------------------------------------------------------------------

    @("processEntries: ZIP find and read specific entry")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        auto tmpPath = "test-data/test-pe-zip-find.zip";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WZip(tmpPath)
            .addBuffer("a.txt", cast(const(ubyte)[]) "content A")
            .addBuffer("b.txt", cast(const(ubyte)[]) "content B")
            .addBuffer("c.txt", cast(const(ubyte)[]) "content C")
            .finish();
        auto reader = RZip(tmpPath);
        scope(exit) reader.close();
        string found;
        auto count = reader.processEntries(["b.txt"],
            (scope ref item) { found = item.data.readText(); });
        count.shouldEqual(1);
        found.shouldEqual("content B");
    }

    @("processEntries: TAR find and read specific entry")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        import darkarchive.formats.tar.writer : tarWriter;
        auto tmpTar = "test-data/test-pe-tar-find.tar";
        scope(exit) if (Path(tmpTar).exists) Path(tmpTar).remove();
        auto tw = tarWriter(tmpTar);
        scope(exit) tw.close();
        tw.addBuffer("first.txt", cast(const(ubyte)[]) "first");
        tw.addBuffer("second.txt", cast(const(ubyte)[]) "second");
        tw.addBuffer("third.txt", cast(const(ubyte)[]) "third");
        tw.finish();
        auto reader = RTar(tmpTar);
        scope(exit) reader.close();
        string found;
        auto count = reader.processEntries(["second.txt"],
            (scope ref item) { found = item.data.readText(); });
        count.shouldEqual(1);
        found.shouldEqual("second");
    }

    @("processEntries: returns 0 when no match")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeFalse;
        auto tmpPath = "test-data/test-pe-no-match.zip";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WZip(tmpPath).addBuffer("exists.txt", cast(const(ubyte)[]) "data").finish();
        auto reader = RZip(tmpPath);
        scope(exit) reader.close();
        bool delegateCalled;
        auto count = reader.processEntries(["nonexistent.txt"],
            (scope ref item) { delegateCalled = true; });
        count.shouldEqual(0);
        delegateCalled.shouldBeFalse;
    }

    @("processEntries: multiple entries all found")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        auto tmpPath = "test-data/test-pe-multi-found.zip";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WZip(tmpPath)
            .addBuffer("x.txt", cast(const(ubyte)[]) "X")
            .addBuffer("y.txt", cast(const(ubyte)[]) "Y")
            .addBuffer("z.txt", cast(const(ubyte)[]) "Z")
            .finish();
        auto reader = RZip(tmpPath);
        scope(exit) reader.close();
        string[] found;
        auto count = reader.processEntries(["z.txt", "x.txt"],
            (scope ref item) { found ~= item.data.readText(); });
        count.shouldEqual(2);
        import std.algorithm : canFind;
        assert(found.canFind("X"));
        assert(found.canFind("Z"));
    }

    @("processEntries: TAR.GZ through gzip layer")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        auto tmpTarGz = "test-data/test-pe-targz.tar.gz";
        scope(exit) if (Path(tmpTarGz).exists) Path(tmpTarGz).remove();
        WTarGz(tmpTarGz).addBuffer("gz-file.txt", cast(const(ubyte)[]) "gzipped content").finish();
        auto reader = RTarGz(tmpTarGz);
        scope(exit) reader.close();
        string found;
        auto count = reader.processEntries(["gz-file.txt"],
            (scope ref item) { found = item.data.readText(); });
        count.shouldEqual(1);
        found.shouldEqual("gzipped content");
    }

    @("processEntries: all-entries overload")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        auto tmpPath = "test-data/test-pe-all-entries.zip";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WZip(tmpPath)
            .addBuffer("one.txt", cast(const(ubyte)[]) "1")
            .addBuffer("two.txt", cast(const(ubyte)[]) "2")
            .addBuffer("three.txt", cast(const(ubyte)[]) "3")
            .finish();
        auto reader = RZip(tmpPath);
        scope(exit) reader.close();
        int count;
        reader.processEntries((scope ref item) { count++; });
        count.shouldEqual(3);
    }

    @("processEntries: delegate reads binary data via readAll")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        auto testData = new ubyte[](1024);
        foreach (i, ref b; testData) b = cast(ubyte)(i & 0xFF);
        auto tmpPath = "test-data/test-pe-binary.zip";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WZip(tmpPath).addBuffer("binary.bin", testData).finish();
        auto reader = RZip(tmpPath);
        scope(exit) reader.close();
        ubyte[] found;
        reader.processEntries(["binary.bin"],
            (scope ref item) { found = item.data.readAll(); });
        found.length.shouldEqual(1024);
        found.shouldEqual(testData);
    }

    @("processEntries: real test-zip.zip")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        auto reader = RZip(Path(testDataDir, "test-zip.zip"));
        string content;
        auto count = reader.processEntries(["file1.txt"],
            (scope ref item) { content = item.data.readText(); });
        count.shouldEqual(1);
        content.shouldEqual("Hello from file1\n");
    }

    @("processEntries: real test.tar.gz")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        auto reader = RTarGz(Path(testDataDir, "test.tar.gz"));
        string content;
        auto count = reader.processEntries(["./file2.txt"],
            (scope ref item) { content = item.data.readText(); });
        count.shouldEqual(1);
        content.shouldEqual("Hello from file2\n");
    }

    @("processEntries: chunked read avoids full memory load")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        auto testData = new ubyte[](32768);
        foreach (i, ref b; testData) b = cast(ubyte)(i & 0xFF);
        auto tmpPath = "test-data/test-pe-chunked.zip";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WZip(tmpPath).addBuffer("large.bin", testData).finish();
        auto reader = RZip(tmpPath);
        scope(exit) reader.close();
        size_t totalBytes, chunkCount;
        reader.processEntries(["large.bin"],
            (scope ref item) {
                item.data.readChunks((const(ubyte)[] chunk) {
                    totalBytes += chunk.length;
                    chunkCount++;
                    assert(chunk.length > 0);
                    assert(chunk.length <= 8192);
                });
            });
        totalBytes.shouldEqual(32768);
        assert(chunkCount >= 4);
    }

    @("processEntries: chunked read on TAR")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        import darkarchive.formats.tar.writer : tarWriter;
        auto testData = new ubyte[](16384);
        foreach (i, ref b; testData) b = cast(ubyte)(i & 0xFF);
        auto tmpTar = "test-data/test-pe-chunked-tar.tar";
        scope(exit) if (Path(tmpTar).exists) Path(tmpTar).remove();
        auto tw = tarWriter(tmpTar);
        scope(exit) tw.close();
        tw.addBuffer("tardata.bin", testData);
        tw.finish();
        auto reader = RTar(tmpTar);
        scope(exit) reader.close();
        size_t totalBytes;
        reader.processEntries(["tardata.bin"],
            (scope ref item) {
                item.data.readChunks((const(ubyte)[] chunk) { totalBytes += chunk.length; });
            });
        totalBytes.shouldEqual(16384);
    }

    @("processEntries: extractTo uses streaming write")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        auto testData = new ubyte[](65536);
        foreach (i, ref b; testData) b = cast(ubyte)(i & 0xFF);
        auto tmpPath = "test-data/test-pe-streaming.zip";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WZip(tmpPath).addBuffer("big.bin", testData).finish();
        auto extractDir = Path(testDataDir, "streaming-extract-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RZip(tmpPath);
        scope(exit) reader.close();
        reader.extractTo(extractDir);
        auto extractedPath = (extractDir ~ "big.bin").toString;
        assert(Path(extractedPath).exists);
        Path(extractedPath).getSize().shouldEqual(65536);
    }

    @("processEntries: chunked read on empty entry")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        auto tmpPath = "test-data/test-pe-empty.zip";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WZip(tmpPath).addBuffer("empty.txt", cast(const(ubyte)[]) "").finish();
        auto reader = RZip(tmpPath);
        scope(exit) reader.close();
        int chunkCount;
        reader.processEntries(["empty.txt"],
            (scope ref item) {
                item.data.readChunks((const(ubyte)[] chunk) { chunkCount++; });
            });
        chunkCount.shouldEqual(0);
    }

    // -------------------------------------------------------------------
    // extractTo with delegate tests
    // -------------------------------------------------------------------

    @("extractTo delegate: strip prefix (unfoldPath)")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        auto tmpPath = "test-data/test-dlg-unfold.zip";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WZip(tmpPath)
            .addBuffer("odoo-18.0/README.txt", cast(const(ubyte)[]) "readme")
            .addBuffer("odoo-18.0/setup.py", cast(const(ubyte)[]) "setup")
            .addDirectory("odoo-18.0/addons")
            .finish();
        auto extractDir = Path(testDataDir, "unfold-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RZip(tmpPath);
        scope(exit) reader.close();
        reader.extractTo(extractDir, DarkExtractFlags.defaults,
            (ref params) {
                import std.algorithm : startsWith;
                if (params.destPath.startsWith("odoo-18.0/"))
                    params.destPath = params.destPath["odoo-18.0/".length .. $];
                return true;
            });
        assert((extractDir ~ "README.txt").exists);
        (extractDir ~ "README.txt").readFileText().shouldEqual("readme");
        assert((extractDir ~ "setup.py").exists);
        assert(!(extractDir ~ "odoo-18.0").exists);
    }

    @("extractTo delegate: skip .pyc files")
    unittest {
        import std.algorithm : endsWith;
        auto tmpPath = "test-data/test-dlg-skip-pyc.zip";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WZip(tmpPath)
            .addBuffer("module.py", cast(const(ubyte)[]) "python source")
            .addBuffer("module.pyc", cast(const(ubyte)[]) "bytecode")
            .addBuffer("other.txt", cast(const(ubyte)[]) "text")
            .finish();
        auto extractDir = Path(testDataDir, "skip-pyc-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RZip(tmpPath);
        scope(exit) reader.close();
        reader.extractTo(extractDir, DarkExtractFlags.defaults,
            (ref params) { return !params.destPath.endsWith(".pyc"); });
        assert((extractDir ~ "module.py").exists);
        assert((extractDir ~ "other.txt").exists);
        assert(!(extractDir ~ "module.pyc").exists);
    }

    @("extractTo delegate: security catches delegate-introduced traversal")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;
        auto tmpPath = "test-data/test-dlg-sec-trav.zip";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WZip(tmpPath).addBuffer("safe.txt", cast(const(ubyte)[]) "data").finish();
        auto extractDir = Path(testDataDir, "delegate-sec-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RZip(tmpPath);
        scope(exit) reader.close();
        bool caught;
        try {
            reader.extractTo(extractDir, DarkExtractFlags.defaults,
                (ref params) { params.destPath = "../escape.txt"; return true; });
        } catch (DarkArchiveException) { caught = true; }
        caught.shouldBeTrue;
    }

    @("extractTo delegate: security catches delegate-introduced absolute path")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;
        auto tmpPath = "test-data/test-dlg-sec-abs.zip";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WZip(tmpPath).addBuffer("safe.txt", cast(const(ubyte)[]) "data").finish();
        auto extractDir = Path(testDataDir, "delegate-abs-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RZip(tmpPath);
        scope(exit) reader.close();
        bool caught;
        try {
            reader.extractTo(extractDir, DarkExtractFlags.defaults,
                (ref params) { params.destPath = "/tmp/evil.txt"; return true; });
        } catch (DarkArchiveException) { caught = true; }
        caught.shouldBeTrue;
    }

    @("extractTo delegate: null delegate same as default")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        auto tmpPath = "test-data/test-dlg-null.zip";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WZip(tmpPath).addBuffer("test.txt", cast(const(ubyte)[]) "content").finish();
        auto extractDir = Path(testDataDir, "null-delegate-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RZip(tmpPath);
        scope(exit) reader.close();
        reader.extractTo(extractDir, DarkExtractFlags.defaults, null);
        assert((extractDir ~ "test.txt").exists);
        (extractDir ~ "test.txt").readFileText().shouldEqual("content");
    }

    @("extractTo delegate: skip all entries")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        auto tmpPath = "test-data/test-dlg-skip-all.zip";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WZip(tmpPath)
            .addBuffer("a.txt", cast(const(ubyte)[]) "A")
            .addBuffer("b.txt", cast(const(ubyte)[]) "B")
            .finish();
        auto extractDir = Path(testDataDir, "skip-all-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RZip(tmpPath);
        scope(exit) reader.close();
        reader.extractTo(extractDir, DarkExtractFlags.defaults,
            (ref params) { return false; });
        if (extractDir.exists) {
            int fileCount;
            foreach (de; extractDir.walkDepth()) fileCount++;
            fileCount.shouldEqual(0);
        }
    }

    @("extractTo delegate: backward compatibility")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        auto tmpPath = "test-data/test-dlg-compat.zip";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WZip(tmpPath).addBuffer("compat.txt", cast(const(ubyte)[]) "works").finish();
        auto extractDir1 = Path(testDataDir, "compat-test-1");
        scope(exit) if (extractDir1.exists) extractDir1.remove();
        auto reader1 = RZip(tmpPath);
        scope(exit) reader1.close();
        reader1.extractTo(extractDir1);
        (extractDir1 ~ "compat.txt").readFileText().shouldEqual("works");
        auto extractDir2 = Path(testDataDir, "compat-test-2");
        scope(exit) if (extractDir2.exists) extractDir2.remove();
        auto reader2 = RZip(tmpPath);
        scope(exit) reader2.close();
        reader2.extractTo(extractDir2, DarkExtractFlags.defaults);
        (extractDir2 ~ "compat.txt").readFileText().shouldEqual("works");
    }

    @("extractTo delegate: read sourceEntry metadata")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;
        auto tmpPath = "test-data/test-dlg-metadata.zip";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        WZip(tmpPath)
            .addBuffer("file.txt", cast(const(ubyte)[]) "content")
            .addDirectory("dir")
            .finish();
        auto extractDir = Path(testDataDir, "source-entry-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        bool sawFile, sawDir;
        auto reader = RZip(tmpPath);
        scope(exit) reader.close();
        reader.extractTo(extractDir, DarkExtractFlags.defaults,
            (ref params) {
                if (params.sourceEntry.isFile) sawFile = true;
                if (params.sourceEntry.isDir) sawDir = true;
                return true;
            });
        sawFile.shouldBeTrue;
        sawDir.shouldBeTrue;
    }

    @("extractTo delegate: works on TAR.GZ")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        auto tmpTarGz = "test-data/test-dlg-targz.tar.gz";
        scope(exit) if (Path(tmpTarGz).exists) Path(tmpTarGz).remove();
        WTarGz(tmpTarGz).addBuffer("prefix/data.txt", cast(const(ubyte)[]) "tar data").finish();
        auto extractDir = Path(testDataDir, "delegate-targz-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RTarGz(tmpTarGz);
        scope(exit) reader.close();
        reader.extractTo(extractDir, DarkExtractFlags.defaults,
            (ref params) {
                import std.algorithm : startsWith;
                if (params.destPath.startsWith("prefix/"))
                    params.destPath = params.destPath["prefix/".length .. $];
                return true;
            });
        assert((extractDir ~ "data.txt").exists);
        (extractDir ~ "data.txt").readFileText().shouldEqual("tar data");
    }

    // -------------------------------------------------------------------
    // addTree symlink following tests
    // -------------------------------------------------------------------

    @("addTree: follows symlinks by default")
    unittest {
        import unit_threaded.assertions : shouldBeTrue, shouldBeFalse;

        version(Posix) {
            auto srcDir = Path.current().join(testDataDir, "symlink-follow-src");
            scope(exit) if (srcDir.exists) srcDir.remove();
            srcDir.mkdir(true);
            (srcDir ~ "real.txt").writeFile("real content");
            Path("real.txt").symlink(srcDir ~ "link.txt");
            auto tmpZip = "test-data/test-tree-follow-sym.zip";
            scope(exit) if (Path(tmpZip).exists) Path(tmpZip).remove();
            WZip(tmpZip).addTree(srcDir).finish();
            auto reader = RZip(tmpZip);
            scope(exit) reader.close();
            bool foundLink;
            foreach (ref item; reader.entries) {
                import std.algorithm : endsWith;
                if (item.meta.pathname.endsWith("link.txt")) {
                    foundLink = true;
                    item.meta.isFile.shouldBeTrue;
                    item.meta.isSymlink.shouldBeFalse;
                }
            }
            foundLink.shouldBeTrue;
        }
    }

    @("addTree: FollowSymlinks.no preserves symlinks")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue;

        version(Posix) {
            auto srcDir = Path.current().join(testDataDir, "symlink-preserve-src");
            scope(exit) if (srcDir.exists) srcDir.remove();
            srcDir.mkdir(true);
            (srcDir ~ "target.txt").writeFile("target content");
            Path("target.txt").symlink(srcDir ~ "preserved.txt");
            auto tmpTar = "test-data/test-tree-preserve-sym.tar";
            scope(exit) if (Path(tmpTar).exists) Path(tmpTar).remove();
            WTar(tmpTar).addTree(srcDir, null, FollowSymlinks.no).finish();
            auto reader = RTar(tmpTar);
            scope(exit) reader.close();
            bool foundSymlink;
            foreach (ref item; reader.entries) {
                import std.algorithm : endsWith;
                if (item.meta.pathname.endsWith("preserved.txt")) {
                    foundSymlink = true;
                    item.meta.isSymlink.shouldBeTrue;
                    item.meta.symlinkTarget.shouldEqual("target.txt");
                }
            }
            foundSymlink.shouldBeTrue;
        }
    }

    @("addTree: no symlinks in source works normally")
    unittest {

        auto srcDir = Path.current().join(testDataDir, "nosym-tree-src");
        scope(exit) if (srcDir.exists) srcDir.remove();
        (srcDir ~ "sub").mkdir(true);
        (srcDir ~ "a.txt").writeFile("aaa");
        (srcDir ~ "sub/b.txt").writeFile("bbb");
        auto tmpZip = "test-data/test-tree-nosym.zip";
        scope(exit) if (Path(tmpZip).exists) Path(tmpZip).remove();
        WZip(tmpZip).addTree(srcDir).finish();
        auto reader = RZip(tmpZip);
        scope(exit) reader.close();
        int fileCount;
        foreach (ref item; reader.entries) { if (item.meta.isFile) fileCount++; }
        assert(fileCount >= 2);
    }

    @("addTree: dangling symlink throws")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;

        version(Posix) {
            auto srcDir = Path.current().join(testDataDir, "dangling-sym-src");
            scope(exit) if (srcDir.exists) srcDir.remove();
            srcDir.mkdir(true);
            (srcDir ~ "real.txt").writeFile("real content");
            Path("nonexistent-target.txt").symlink(srcDir ~ "dangling.txt");
            auto tmpZip = "test-data/test-tree-dangling.zip";
            scope(exit) if (Path(tmpZip).exists) Path(tmpZip).remove();
            auto writer = WZip(tmpZip);
            bool threw;
            try { writer.addTree(srcDir); } catch (Exception) { threw = true; }
            threw.shouldBeTrue;
        }
    }

    @("addTree: circular symlinks throw, not hang")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;

        version(Posix) {
            auto srcDir = Path.current().join(testDataDir, "circular-sym-src");
            scope(exit) if (srcDir.exists) srcDir.remove();
            srcDir.mkdir(true);
            (srcDir ~ "real.txt").writeFile("real content");
            Path("circular-b.txt").symlink(srcDir ~ "circular-a.txt");
            Path("circular-a.txt").symlink(srcDir ~ "circular-b.txt");
            auto tmpZip = "test-data/test-tree-circular.zip";
            scope(exit) if (Path(tmpZip).exists) Path(tmpZip).remove();
            auto writer = WZip(tmpZip);
            bool threw;
            try { writer.addTree(srcDir); } catch (Exception) { threw = true; }
            threw.shouldBeTrue;
        }
    }

    // -------------------------------------------------------------------
    // Permission tests
    // -------------------------------------------------------------------

    version(Posix) @("extractTo: preserves execute permission by default")
    unittest {
        import std.conv : octal;
        import darkarchive.formats.tar.writer : tarWriter;
        auto tmpTar = "test-data/test-perm-exec.tar";
        scope(exit) if (Path(tmpTar).exists) Path(tmpTar).remove();
        auto tw = tarWriter(tmpTar);
        scope(exit) tw.close();
        tw.addBuffer("script.sh", cast(const(ubyte)[]) "#!/bin/sh\necho hello", octal!755);
        tw.addBuffer("data.txt",  cast(const(ubyte)[]) "just data",             octal!644);
        tw.finish();
        auto extractDir = Path(testDataDir, "perm-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RTar(tmpTar);
        scope(exit) reader.close();
        reader.extractTo(extractDir);
        auto scriptAttrs = (extractDir ~ "script.sh").getAttributes();
        assert(scriptAttrs & octal!100);
        auto dataAttrs = (extractDir ~ "data.txt").getAttributes();
        assert(!(dataAttrs & octal!100));
    }

    version(Posix) @("extractTo: strips setuid/setgid/sticky bits")
    unittest {
        import std.conv : octal;
        import darkarchive.formats.tar.writer : tarWriter;
        auto tmpTar = "test-data/test-perm-dangerous.tar";
        scope(exit) if (Path(tmpTar).exists) Path(tmpTar).remove();
        auto tw = tarWriter(tmpTar);
        scope(exit) tw.close();
        tw.addBuffer("setuid.sh", cast(const(ubyte)[]) "#!/bin/sh", octal!4755);
        tw.addBuffer("setgid.sh", cast(const(ubyte)[]) "#!/bin/sh", octal!2755);
        tw.finish();
        auto extractDir = Path(testDataDir, "perm-dangerous-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RTar(tmpTar);
        scope(exit) reader.close();
        reader.extractTo(extractDir);
        auto attrs1 = (extractDir ~ "setuid.sh").getAttributes();
        assert(attrs1 & octal!100);
        assert(!(attrs1 & octal!4000));
        auto attrs2 = (extractDir ~ "setgid.sh").getAttributes();
        assert(attrs2 & octal!100);
        assert(!(attrs2 & octal!2000));
    }

    version(Posix) @("extractTo: caps group/other write bits")
    unittest {
        import std.conv : octal;
        import darkarchive.formats.tar.writer : tarWriter;
        auto tmpTar = "test-data/test-perm-cap.tar";
        scope(exit) if (Path(tmpTar).exists) Path(tmpTar).remove();
        auto tw = tarWriter(tmpTar);
        scope(exit) tw.close();
        tw.addBuffer("world-writable.txt", cast(const(ubyte)[]) "data",       octal!666);
        tw.addBuffer("full-perm.sh",        cast(const(ubyte)[]) "#!/bin/sh", octal!777);
        tw.addBuffer("normal.txt",          cast(const(ubyte)[]) "data",       octal!644);
        tw.addBuffer("owner-only.sh",       cast(const(ubyte)[]) "#!/bin/sh", octal!700);
        tw.finish();
        auto extractDir = Path(testDataDir, "perm-cap-test");
        scope(exit) if (extractDir.exists) extractDir.remove();
        auto reader = RTar(tmpTar);
        scope(exit) reader.close();
        reader.extractTo(extractDir);
        auto a1 = (extractDir ~ "world-writable.txt").getAttributes();
        assert(!(a1 & octal!20)); assert(!(a1 & octal!2)); assert(a1 & octal!400);
        auto a2 = (extractDir ~ "full-perm.sh").getAttributes();
        assert(a2 & octal!100); assert(a2 & octal!10);
        assert(!(a2 & octal!20)); assert(!(a2 & octal!2));
        auto a3 = (extractDir ~ "normal.txt").getAttributes();
        assert(a3 & octal!400); assert(!(a3 & octal!100));
        auto a4 = (extractDir ~ "owner-only.sh").getAttributes();
        assert(a4 & octal!100); assert(!(a4 & octal!40));
    }

    // -------------------------------------------------------------------
    // Streaming constructors
    // -------------------------------------------------------------------

    @("streaming read: darkArchiveReader(tarGz, range) reads entries correctly")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue;
        import darkarchive.datasource : byChunks;
        auto compressed = cast(const(ubyte)[]) Path(testDataDir ~ "/test.tar.gz").readFile();
        auto reader = darkArchiveReader!(DarkArchiveFormat.tarGz)(byChunks(compressed, 4096));
        scope(exit) reader.close();
        bool found;
        foreach (entry; reader.entries) {
            if (entry.pathname == "./file1.txt") {
                found = true;
                reader.readText().shouldEqual("Hello from file1\n");
            } else {
                reader.skipData();
            }
        }
        found.shouldBeTrue;
    }

    @("streaming read: darkArchiveReader(tar, range) reads entries correctly")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue;
        import darkarchive.datasource : byChunks;
        auto tarPath = testDataDir ~ "/test-stream-src.tar";
        scope(exit) if (Path(tarPath).exists) Path(tarPath).remove();
        WTar(tarPath).addBuffer("hello.txt", cast(const(ubyte)[]) "stream content").finish();
        auto raw = cast(const(ubyte)[]) Path(tarPath).readFile();
        auto reader = darkArchiveReader!(DarkArchiveFormat.tar)(byChunks(raw, 512));
        scope(exit) reader.close();
        bool found;
        foreach (entry; reader.entries) {
            if (entry.pathname == "hello.txt") {
                found = true;
                reader.readText().shouldEqual("stream content");
            } else {
                reader.skipData();
            }
        }
        found.shouldBeTrue;
    }

    @("streaming write: darkArchiveWriter(tar, DelegateSink) produces readable TAR")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue;
        import darkarchive.datasource : DelegateSink;
        ubyte[] buf;
        darkArchiveWriter!(DarkArchiveFormat.tar)(
                DelegateSink((const(ubyte)[] c) { buf ~= c; }))
            .addBuffer("hello.txt", cast(const(ubyte)[]) "sink content")
            .finish();
        auto tmpPath = testDataDir ~ "/test-sink-tar.tar";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        Path(tmpPath).writeFile(buf);
        auto reader = RTar(tmpPath);
        scope(exit) reader.close();
        bool found;
        foreach (ref item; reader.entries) {
            if (item.meta.pathname == "hello.txt") {
                found = true;
                item.data.readText().shouldEqual("sink content");
            }
        }
        found.shouldBeTrue;
    }

    @("streaming write: darkArchiveWriter(tarGz, DelegateSink) produces readable TAR.GZ")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue;
        import darkarchive.datasource : DelegateSink;
        ubyte[] buf;
        darkArchiveWriter!(DarkArchiveFormat.tarGz)(
                DelegateSink((const(ubyte)[] c) { buf ~= c; }))
            .addBuffer("hello.txt", cast(const(ubyte)[]) "gzip sink content")
            .finish();
        auto tmpPath = testDataDir ~ "/test-sink-tar.tar.gz";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        Path(tmpPath).writeFile(buf);
        auto reader = RTarGz(tmpPath);
        scope(exit) reader.close();
        bool found;
        foreach (ref item; reader.entries) {
            if (item.meta.pathname == "hello.txt") {
                found = true;
                item.data.readText().shouldEqual("gzip sink content");
            }
        }
        found.shouldBeTrue;
    }

    // -------------------------------------------------------------------
    // Sink-backed writer: addTree and add(path)
    // -------------------------------------------------------------------

    @("sink-backed writer: darkArchiveWriter returns DarkArchiveWriter with addTree")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue;
        import darkarchive.datasource : DelegateSink;
        // addTree on a sink-backed writer must produce a readable archive
        auto srcDir = Path(testDataDir, "sink-tree-src");
        auto tmpPath = testDataDir ~ "/test-sink-addtree.tar.gz";
        scope(exit) {
            if (srcDir.exists) srcDir.remove();
            if (Path(tmpPath).exists) Path(tmpPath).remove();
        }
        srcDir.mkdir(true);
        (srcDir ~ "a.txt").writeFile("hello");
        (srcDir ~ "b.txt").writeFile("world");
        ubyte[] buf;
        darkArchiveWriter!(DarkArchiveFormat.tarGz)(
                DelegateSink((const(ubyte)[] c) { buf ~= c; }))
            .addTree(srcDir)
            .finish();
        Path(tmpPath).writeFile(buf);
        auto reader = RTarGz(tmpPath);
        scope(exit) reader.close();
        int count;
        foreach (ref item; reader.entries) {
            if (item.meta.isFile) count++;
        }
        count.shouldEqual(2);
    }

    @("sink-backed writer: add(path) streams file from disk into sink")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue;
        import darkarchive.datasource : DelegateSink;
        auto srcFile = testDataDir ~ "/test-zip.zip";  // any existing file
        ubyte[] buf;
        darkArchiveWriter!(DarkArchiveFormat.tar)(
                DelegateSink((const(ubyte)[] c) { buf ~= c; }))
            .add(srcFile, "payload.bin")
            .finish();
        auto tmpPath = testDataDir ~ "/test-sink-addfile.tar";
        scope(exit) if (Path(tmpPath).exists) Path(tmpPath).remove();
        Path(tmpPath).writeFile(buf);
        auto reader = RTar(tmpPath);
        scope(exit) reader.close();
        bool found;
        foreach (ref item; reader.entries) {
            if (item.meta.pathname == "payload.bin") {
                found = true;
                item.meta.size.shouldEqual(Path(srcFile).getSize());
            }
        }
        found.shouldBeTrue;
    }

    @("sink-backed writer: ZIP + sink is a compile-time error")
    unittest {
        import darkarchive.datasource : DelegateSink;
        static assert(!__traits(compiles,
            DarkArchiveWriter!(DarkArchiveFormat.zip, DelegateSink)(DelegateSink.init)));
    }

    // -------------------------------------------------------------------
    // Streaming memory tests
    // -------------------------------------------------------------------

    @("streaming write: TAR to file does not accumulate memory")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;
        import core.memory : GC;
        auto outPath = Path(testDataDir, "mem-write-test.tar");
        scope(exit) if (outPath.exists) outPath.remove();
        auto chunk = new ubyte[](64 * 1024);
        GC.collect();
        auto memBefore = GC.stats.usedSize;
        auto writerTar = WTar(outPath);
        foreach (i; 0 .. 64) {
            import std.format : format;
            writerTar.addBuffer("file_%03d.bin".format(i), chunk);
        }
        writerTar.finish();
        GC.collect();
        auto memAfter = GC.stats.usedSize;
        auto growth = memAfter > memBefore ? memAfter - memBefore : 0;
        assert(growth < 2 * 1024 * 1024,
            "TAR write: memory grew by " ~ formatMemSize(growth));
        assert(outPath.exists);
        assert(outPath.getSize() > 4 * 1024 * 1024);
    }

    @("streaming write: ZIP to file does not accumulate memory")
    unittest {
        import core.memory : GC;
        auto outPath = Path(testDataDir, "mem-write-test.zip");
        scope(exit) if (outPath.exists) outPath.remove();
        auto chunk = new ubyte[](64 * 1024);
        GC.collect();
        auto memBefore = GC.stats.usedSize;
        auto writerZip = WZip(outPath);
        foreach (i; 0 .. 64) {
            import std.format : format;
            writerZip.addBuffer("file_%03d.bin".format(i), chunk);
        }
        writerZip.finish();
        GC.collect();
        auto memAfter = GC.stats.usedSize;
        auto growth = memAfter > memBefore ? memAfter - memBefore : 0;
        assert(growth < 2 * 1024 * 1024,
            "ZIP write: memory grew by " ~ formatMemSize(growth));
        assert(outPath.exists);
        assert(outPath.getSize() > 0);
    }

    @("streaming write: TAR.GZ to file does not accumulate memory")
    unittest {
        import core.memory : GC;
        auto outPath = Path(testDataDir, "mem-write-test.tar.gz");
        scope(exit) if (outPath.exists) outPath.remove();
        auto chunk = new ubyte[](64 * 1024);
        GC.collect();
        auto memBefore = GC.stats.usedSize;
        auto writerGz = WTarGz(outPath);
        foreach (i; 0 .. 64) {
            import std.format : format;
            writerGz.addBuffer("file_%03d.bin".format(i), chunk);
        }
        writerGz.finish();
        GC.collect();
        auto memAfter = GC.stats.usedSize;
        auto growth = memAfter > memBefore ? memAfter - memBefore : 0;
        assert(growth < 2 * 1024 * 1024,
            "TAR.GZ write: memory grew by " ~ formatMemSize(growth));
        assert(outPath.exists);
        assert(outPath.getSize() > 0);
    }

    @("streaming write: TAR round-trip via streaming write")
    unittest {
        import unit_threaded.assertions : shouldEqual;
        auto outPath = Path(testDataDir, "stream-write-roundtrip.tar");
        scope(exit) if (outPath.exists) outPath.remove();
        WTar(outPath)
            .addBuffer("hello.txt", cast(const(ubyte)[]) "Hello!")
            .addBuffer("world.txt", cast(const(ubyte)[]) "World!")
            .finish();
        auto reader = RTar(outPath);
        scope(exit) reader.close();
        int count;
        foreach (ref item; reader.entries) {
            count++;
            if (item.meta.pathname == "hello.txt") item.data.readText().shouldEqual("Hello!");
            else if (item.meta.pathname == "world.txt") item.data.readText().shouldEqual("World!");
        }
        count.shouldEqual(2);
    }

    @("streaming: TAR addStream with known size does not buffer full entry")
    unittest {
        import core.memory : GC;
        auto outPath = "test-data/mem-addstream-tar.tar";
        scope(exit) if (Path(outPath).exists) Path(outPath).remove();
        enum ENTRY_SIZE = 4 * 1024 * 1024;
        auto chunk = new ubyte[](8192);
        foreach (i, ref b; chunk) b = cast(ubyte)(i & 0xFF);
        GC.collect();
        auto memBefore = GC.stats.usedSize;
        WTar(outPath)
            .addStream("large.bin", (scope sink) {
                foreach (_; 0 .. ENTRY_SIZE / chunk.length) sink(chunk);
            }, ENTRY_SIZE)
            .finish();
        GC.collect();
        auto memAfter = GC.stats.usedSize;
        auto growth = memAfter > memBefore ? memAfter - memBefore : 0;
        assert(growth < 2 * 1024 * 1024,
            "TAR addStream(known size): memory grew by " ~ formatMemSize(growth));
        assert(Path(outPath).getSize() > ENTRY_SIZE);
    }

    @("streaming: ZIP addStream with known size does not buffer full entry")
    unittest {
        import core.memory : GC;
        auto outPath = "test-data/mem-addstream-zip.zip";
        scope(exit) if (Path(outPath).exists) Path(outPath).remove();
        enum ENTRY_SIZE = 4 * 1024 * 1024;
        auto chunk = new ubyte[](8192);
        foreach (i, ref b; chunk) b = cast(ubyte)(i & 0xFF);
        GC.collect();
        auto memBefore = GC.stats.usedSize;
        WZip(outPath)
            .addStream("large.bin", (scope sink) {
                foreach (_; 0 .. ENTRY_SIZE / chunk.length) sink(chunk);
            }, ENTRY_SIZE)
            .finish();
        GC.collect();
        auto memAfter = GC.stats.usedSize;
        auto growth = memAfter > memBefore ? memAfter - memBefore : 0;
        assert(growth < 2 * 1024 * 1024,
            "ZIP addStream(known size): memory grew by " ~ formatMemSize(growth));
        assert(Path(outPath).getSize() > 0);
    }
}
