/// High-level format-agnostic archive reader and writer.
///
/// Auto-detects format by magic bytes (read) or file extension (write).
/// Delegates to format-specific implementations in darkarchive.formats.*.
module darkarchive.archive;

import std.conv : octal;
import std.string : toLower, endsWith;

import darkarchive.entry : DarkArchiveEntry, EntryType;
import darkarchive.exception : DarkArchiveException;
import darkarchive.formats.zip : ZipReader, ZipWriter;
import darkarchive.formats.tar : TarReader, TarWriter;
import darkarchive.datasource : GzipSequentialReader, DelegateSequentialReader, chunkSource;

import thepath : Path;


/// Archive format selection.
enum DarkArchiveFormat {
    zip,
    tar,
    tarGz,
    // tarZst,  -- future stage
}

/// Optional capabilities that vary by format.
enum ArchiveCapability {
    streamingRead,   /// Can construct reader from a ubyte[] delegate() chunk source
    streamingWrite,  /// Can construct writer with a void delegate(const ubyte[]) sink
    randomAccessRead /// Can seek to arbitrary entries (e.g. ZIP central directory)
}

/// Query whether a format supports a given capability.
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
                case DarkArchiveFormat.zip:   return false; // future: data-descriptor path
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
///
/// By default, extraction rejects path traversal and skips symlinks.
/// Permissions are always applied safely (execute bit preserved, setuid/
/// setgid/sticky stripped, group/other write capped).
enum DarkExtractFlags {
    none        = 0,
    securePaths = 1,     /// Reject ".." path components and absolute paths
    symlinks    = 2,     /// Extract symlinks (off by default — symlinks are skipped)
    defaults    = securePaths,
}


/// Controls symlink handling in addTree.
enum FollowSymlinks {
    yes,  /// Follow symlinks, archive target content as regular file (default)
    no,   /// Preserve symlinks as symlink entries (Posix only)
}

/// Parameters passed to extractTo preprocessing delegate.
/// The delegate can modify destPath to rename/relocate entries, and
/// return false to skip entries. Original entry metadata (including
/// permissions, ownership, timestamps) is available read-only via sourceEntry.
///
/// For full control over permissions and metadata during extraction,
/// use `processEntries` instead.
struct ExtractParams {
    /// Destination path relative to extraction root. Modify to rename/relocate.
    string destPath;

    /// Read-only: original archive entry metadata (type, size, permissions,
    /// mtime, ownership, etc.)
    const(DarkArchiveEntry)* sourceEntry;
}


// ---------------------------------------------------------------------------
// DarkArchiveReader
// ---------------------------------------------------------------------------

/// Create a TarWriter that pipes output through streaming gzip compressor
/// directly to a file. No temporary files, constant memory.
private TarWriter createGzipTarWriterToSink(void delegate(const(ubyte)[]) sink) {
    import std.zlib : Compress, HeaderFormat;
    auto compressor = new Compress(6, HeaderFormat.gzip);
    return TarWriter.createToSink(
        (const(ubyte)[] bytes) {
            auto compressed = cast(ubyte[]) compressor.compress(bytes);
            if (compressed.length > 0)
                sink(compressed);
        },
        () {
            auto tail = cast(ubyte[]) compressor.flush();
            if (tail.length > 0)
                sink(tail);
        }
    );
}

private TarWriter createGzipTarWriter(string outputPath) {
    import std.stdio : File;
    import std.zlib : Compress, HeaderFormat;

    auto outFile = new File(outputPath, "wb");
    auto compressor = new Compress(6, HeaderFormat.gzip);

    return TarWriter.createToSink(
        // sink: compress and write each chunk
        (const(ubyte)[] bytes) {
            auto compressed = cast(ubyte[]) compressor.compress(bytes);
            if (compressed.length > 0)
                outFile.rawWrite(compressed);
        },
        // finish: flush compressor and close file
        () {
            auto tail = cast(ubyte[]) compressor.flush();
            if (tail.length > 0)
                outFile.rawWrite(tail);
            outFile.close();
        }
    );
}

/// Check if a path contains ".." as a path component (not as part of a filename).
/// "foo/../bar" → true, "file..name.txt" → false, ".." → true
private bool hasPathTraversal(string path) {
    import std.algorithm : splitter;
    foreach (component; path.splitter('/')) {
        if (component == "..")
            return true;
        // Also check backslash-separated (Windows paths in ZIPs)
        foreach (sub; component.splitter('\\'))
            if (sub == "..")
                return true;
    }
    return false;
}

/// High-level archive reader. Auto-detects format from file content.
///
/// Supports ZIP, TAR, and TAR.GZ formats. For non-ASCII pathnames in ZIP
/// archives, no locale configuration is needed (pure D implementation).
struct DarkArchiveReader {
    private {
        // Format-specific state (only one is active)
        ZipReader* _zip;
        TarReader* _tar;

        DarkArchiveFormat _format;
        // For zip: iteration index
        size_t _zipIndex;
    }

    @disable this();

    /// Open archive from file path (auto-detect format).
    /// For ZIP: uses file-backed I/O (does not load full file into memory).
    /// For TAR: file-backed via DataSource (sequential reads, no full load).
    /// For TAR.GZ: streaming gzip decompression (no temp files, constant memory).
    this(in Path path) {
        this(path.toString());
    }

    /// ditto
    this(string path) {
        // Read just the first 264 bytes for format detection (enough for
        // ZIP magic at 0, GZIP magic at 0, and TAR ustar magic at 257)
        import std.file : read, getSize;
        auto fileSize = getSize(path);
        if (fileSize < 4)
            throw new DarkArchiveException("Archive file too small to detect format");

        auto headerLen = fileSize > 264 ? 264 : cast(size_t) fileSize;
        auto header = cast(const(ubyte)[]) read(path, headerLen);

        // ZIP: file-backed (no full load)
        if (header[0] == 'P' && header[1] == 'K' &&
            (header[2] == 3 || header[2] == 5)) {
            _zip = new ZipReader(path);
            _format = DarkArchiveFormat.zip;
            return;
        }

        // GZIP: streaming decompression — no temp files, constant memory
        if (header.length >= 2 && header[0] == 0x1f && header[1] == 0x8b) {
            auto gzStream = new GzipSequentialReader(path);
            _tar = new TarReader(gzStream);
            _format = DarkArchiveFormat.tarGz;
            return;
        }

        // TAR: file-backed (no full load)
        if (header.length >= 263 &&
            header[257 .. 262] == cast(const(ubyte)[]) "ustar") {
            _tar = new TarReader(path);
            _format = DarkArchiveFormat.tar;
            return;
        }

        throw new DarkArchiveException("Cannot detect archive format");
    }


    /// Construct a streaming reader from a chunk-producing delegate.
    ///
    /// The delegate returns the next compressed/raw chunk on each call,
    /// or an empty slice on EOF. The returned slice must remain valid
    /// until the next delegate call — `.dup` if the source reuses buffers.
    ///
    /// Only TAR and TAR.GZ formats are supported. ZIP requires random
    /// access and will throw immediately. Check `supports(fmt, streamingRead)`
    /// before calling if the format is not known at compile time.
    this(DarkArchiveFormat fmt, ubyte[] delegate() source) {
        _format = fmt;
        final switch (fmt) {
            case DarkArchiveFormat.zip:
                throw new DarkArchiveException(
                    "ZIP does not support streaming read — use supports() to check first");
            case DarkArchiveFormat.tar:
                _tar = new TarReader(new DelegateSequentialReader(source));
                break;
            case DarkArchiveFormat.tarGz:
                _tar = new TarReader(new GzipSequentialReader(source));
                break;
        }
    }

    /// Archive format (detected from extension or set explicitly).
    DarkArchiveFormat format() const {
        return _format;
    }

    /// Close the underlying file handles. Call before deleting the archive
    /// file on Windows (where open files cannot be deleted).
    void close() {
        if (_zip !is null) _zip.close();
        if (_tar !is null) _tar.close();
    }

    /// Iterate over entries.
    auto entries() {
        if (_zip !is null)
            return EntryIterator.makeZip(&this);
        else
            return EntryIterator.makeTar(&this);
    }

    /// Read current entry's data (for zip: by last iterated index).
    ubyte[] readAll() {
        if (_zip !is null) {
            // ZIP readData may return a const slice — need dup for ownership
            return cast(ubyte[]) _zip.readData(_zipIndex).dup;
        } else {
            // TAR readData returns owned data from SequentialReader — no dup needed
            auto d = _tar.readData();
            return d is null ? [] : cast(ubyte[]) d;
        }
    }

    /// Read current entry as text.
    string readText() {
        return cast(string) readAll();
    }

    /// Skip current entry's data.
    /// Skip current entry's data. For TAR: advances the stream past the
    /// entry data. For ZIP: no-op (random access). Also called implicitly
    /// by EntryRange.popFront() if data was not consumed.
    void skipData() {
        if (_tar !is null)
            _tar.skipData();
    }

    // -- Entry data reader for processEntries delegate --

    /// Provides data access for a matched entry inside processEntries.
    static struct EntryDataReader {
        private DarkArchiveReader* _parent;
        private size_t _zipIdx;

        /// Read full entry data into memory. For small entries.
        /// For large entries, use `readChunks` instead.
        ubyte[] readAll() {
            if (_parent._zip !is null) {
                return cast(ubyte[]) _parent._zip.readData(_zipIdx).dup;
            } else {
                auto d = _parent._tar.readData();
                return d is null ? [] : cast(ubyte[]) d;
            }
        }

        /// Read entry data as text.
        string readText() {
            return cast(string) readAll();
        }

        /// Read entry data in chunks, calling `sink` for each chunk.
        /// Each chunk is at most `chunkSize` bytes. Never loads the full
        /// entry into memory — true streaming for 30GB+ entries.
        void readChunks(scope void delegate(const(ubyte)[] chunk) sink,
                         size_t chunkSize = 8192) {
            if (_parent._zip !is null) {
                // ZIP: streaming inflate — reads compressed data from
                // DataSource in chunks, decompresses in chunks
                _parent._zip.readDataChunked(_zipIdx, sink, chunkSize);
            } else {
                // TAR: streaming read from SequentialReader in chunks
                _parent._tar.readDataChunked(sink, chunkSize);
            }
        }
    }

    // -- processEntries methods --

    /// Process all entries in the archive, calling `processor` for each.
    ///
    /// Returns: number of entries processed (total entry count).
    size_t processEntries(
            scope void delegate(const ref DarkArchiveEntry entry,
                                scope EntryDataReader dataReader) processor) {
        size_t count;

        if (_zip !is null) {
            foreach (i; 0 .. _zip.length) {
                auto entry = _zip.entryAt(i);
                auto dr = EntryDataReader(&this, i);
                processor(entry, dr);
                count++;
            }
        } else {
            foreach (entry; _tar.entries()) {
                auto dr = EntryDataReader(&this, 0);
                processor(entry, dr);
                count++;
            }
        }

        return count;
    }

    /// Process specific entries by name. Stops iteration early once all
    /// requested names are found.
    ///
    /// Params:
    ///   names = entry pathnames to search for
    ///   processor = delegate called for each matched entry
    ///
    /// Returns: number of entries matched and processed.
    ///   Compare with `names.length` to check if all were found.
    size_t processEntries(
            const(string)[] names,
            scope void delegate(const ref DarkArchiveEntry entry,
                                scope EntryDataReader dataReader) processor) {
        if (names.length == 0) return 0;

        // Build lookup set
        bool[string] remaining;
        foreach (name; names)
            remaining[name] = true;

        size_t count;

        if (_zip !is null) {
            foreach (i; 0 .. _zip.length) {
                auto entry = _zip.entryAt(i);
                if (entry.pathname in remaining) {
                    auto dr = EntryDataReader(&this, i);
                    processor(entry, dr);
                    count++;
                    remaining.remove(entry.pathname);
                    if (remaining.length == 0)
                        break; // all found — early exit
                }
            }
        } else {
            foreach (entry; _tar.entries()) {
                if (entry.pathname in remaining) {
                    auto dr = EntryDataReader(&this, 0);
                    processor(entry, dr);
                    count++;
                    remaining.remove(entry.pathname);
                    if (remaining.length == 0)
                        break;
                }
            }
        }

        return count;
    }

    /// Extract entire archive to directory.
    ///
    /// Security defaults:
    /// - Paths with `..` components and absolute paths are rejected (`securePaths`)
    /// - Symlink entries are **skipped** by default. Enable with `DarkExtractFlags.symlinks`.
    ///   Even when enabled, symlinks are validated:
    ///     - Absolute targets (e.g., `/etc/passwd`) are always rejected unconditionally
    ///     - Targets with `..` components are rejected when `securePaths` is set
    ///     - The resolved real path is verified to stay within the extraction directory
    ///       (defends against two-step symlink+file attacks, CVE-2021-20206 pattern)
    ///
    /// Example:
    /// ---
    /// // Safe defaults (symlinks skipped):
    /// reader.extractTo(Path("/tmp/output"));
    ///
    /// // Enable symlinks (still validates targets):
    /// reader.extractTo(Path("/tmp/output"),
    ///     DarkExtractFlags.defaults | DarkExtractFlags.symlinks);
    ///
    /// // With preprocessing delegate (strip prefix, filter entries):
    /// reader.extractTo(Path("/tmp/output"), DarkExtractFlags.defaults,
    ///     (ref params) {
    ///         if (params.destPath.startsWith("prefix/"))
    ///             params.destPath = params.destPath["prefix/".length .. $];
    ///         return !params.destPath.endsWith(".pyc"); // skip .pyc
    ///     });
    /// ---
    void extractTo(in Path destination,
                    DarkExtractFlags flags = DarkExtractFlags.defaults) {
        extractToImpl(destination, flags, null);
    }

    /// Extract with entry preprocessing/filtering delegate.
    ///
    /// The delegate receives an `ExtractParams` ref with modifiable `destPath`.
    /// Original entry metadata is read-only via `params.sourceEntry`.
    ///
    /// Return `false` from the delegate to skip the entry.
    /// The delegate runs BEFORE security checks — security is the final gatekeeper.
    void extractTo(in Path destination,
                    DarkExtractFlags flags,
                    scope bool delegate(ref ExtractParams params) preprocess) {
        extractToImpl(destination, flags, preprocess);
    }

    private void extractToImpl(
            in Path destination,
            DarkExtractFlags flags,
            scope bool delegate(ref ExtractParams params) preprocess) {
        import std.file : mkdirRecurse, write, exists;

        auto destStr = destination.toString();

        foreach (entry; entries()) {
            ExtractParams params;
            params.destPath = entry.pathname;
            params.sourceEntry = &entry;

            if (preprocess !is null) {
                if (!preprocess(params)) {
                    skipData();
                    continue;
                }
            }

            auto entryPath = params.destPath;

            if (flags & DarkExtractFlags.securePaths) {
                if (entryPath.length > 0 && entryPath[0] == '/')
                    throw new DarkArchiveException(
                        "Refusing to extract absolute path: " ~ entryPath);
                if (hasPathTraversal(entryPath))
                    throw new DarkArchiveException(
                        "Refusing to extract path with '..' component: " ~ entryPath);
            }

            // Strip leading "./"
            if (entryPath.length >= 2 && entryPath[0 .. 2] == "./")
                entryPath = entryPath[2 .. $];
            if (entryPath.length == 0) {
                skipData();
                continue;
            }

            auto fullPath = Path(destStr, entryPath);

            if (entry.isDir) {
                mkdirRecurse(fullPath.toString());
                skipData();
            } else if (entry.isSymlink) {
                if (!(flags & DarkExtractFlags.symlinks)) {
                    skipData();
                    continue;
                }

                auto target = entry.symlinkTarget;

                if (target.length > 0 && target[0] == '/')
                    throw new DarkArchiveException(
                        "Refusing to create symlink with absolute target: " ~ target);

                if (flags & DarkExtractFlags.securePaths) {
                    if (hasPathTraversal(target))
                        throw new DarkArchiveException(
                            "Refusing to create symlink with '..' in target: " ~ target);
                }
                auto parent = fullPath.parent;
                if (!exists(parent.toString()))
                    mkdirRecurse(parent.toString());
                version(Posix) {
                    import std.file : symlink;
                    symlink(entry.symlinkTarget, fullPath.toString());
                } else {
                    throw new DarkArchiveException(
                        "Symlink extraction is not supported on this platform: "
                        ~ entryPath);
                }
                skipData();
            } else {
                auto parent = fullPath.parent;
                if (!exists(parent.toString()))
                    mkdirRecurse(parent.toString());

                if (flags & DarkExtractFlags.securePaths) {
                    verifyPathWithinRoot(parent.toString(), destStr);
                }

                writeEntryToFile(fullPath.toString());
                applyPermissions(fullPath.toString(), entry.permissions);
            }
        }
    }

    /// Apply archive permissions to an extracted file/directory.
    /// Strips: setuid (04000), setgid (02000), sticky (01000).
    /// Caps: group-write (0020) and other-write (0002) removed
    /// (equivalent to umask 022 — prevents world-writable files).
    private static void applyPermissions(string path, uint archivePerms) {
        version(Posix) {
            if (archivePerms == 0) return; // no permissions stored
            auto safeBits = archivePerms & octal!777;  // strip setuid/setgid/sticky
            safeBits &= ~octal!22;                      // strip group-write and other-write
            if (safeBits == 0) return;
            import std.file : setAttributes;
            try {
                setAttributes(path, safeBits);
            } catch (Exception) {
                // Best effort — don't fail extraction if chmod fails
            }
        }
        // On Windows: no-op (Windows doesn't use POSIX permission bits)
    }

    /// Write current entry's data to a file in chunks.
    private void writeEntryToFile(string outPath) {
        import std.stdio : File;
        auto f = File(outPath, "wb");
        if (_zip !is null) {
            _zip.readDataChunked(_zipIndex, (const(ubyte)[] chunk) {
                f.rawWrite(chunk);
            });
        } else {
            _tar.readDataChunked((const(ubyte)[] chunk) {
                f.rawWrite(chunk);
            });
        }
    }

    /// Check if a resolved path stays within the expected root directory.
    /// Defends against two-step symlink+file attacks (CVE-2021-20206 pattern).
    private static void verifyPathWithinRoot(string path, string root) {
        auto resolved = resolveRealPath(path);
        auto normalRoot = resolveRealPath(root);

        if (!pathStartsWith(resolved, normalRoot))
            throw new DarkArchiveException(
                "Refusing to write file: resolved path escapes extraction directory");
    }

    /// Poor man's realpath: resolve symlinks in path components.
    private static string resolveRealPath(string path) {
        import std.path : absolutePath, buildNormalizedPath, dirName, baseName;
        import std.file : exists;

        auto normalized = buildNormalizedPath(absolutePath(path));

        version(Posix) {
            import std.file : isSymlink, readLink;

            // Walk each component and resolve symlinks
            string[] parts;
            auto remaining = normalized;
            while (remaining.length > 0 && remaining != "/" && remaining != ".") {
                auto base = baseName(remaining);
                auto parent = dirName(remaining);
                if (parent == remaining) break; // root
                parts = base ~ parts;
                remaining = parent;
            }
            parts = remaining ~ parts;

            string resolved = parts[0]; // root
            foreach (part; parts[1 .. $]) {
                resolved = buildNormalizedPath(resolved, part);
                if (exists(resolved) && isSymlink(resolved)) {
                    auto target = readLink(resolved);
                    if (target.length > 0 && target[0] == '/')
                        resolved = target; // absolute symlink
                    else
                        resolved = buildNormalizedPath(dirName(resolved), target);
                }
            }

            return buildNormalizedPath(resolved);
        } else {
            // On Windows, no symlink resolution — just normalize
            return normalized;
        }
    }

    private static bool pathStartsWith(string s, string prefix) {
        if (s.length < prefix.length) return false;
        if (s[0 .. prefix.length] != prefix) return false;
        // Ensure it's a proper prefix (ends at path separator boundary or exact match)
        if (s.length == prefix.length) return true;
        return s[prefix.length] == '/' || s[prefix.length] == '\\';
    }

    // -- Private: unified entry iterator --

    private static struct EntryIterator {
        private {
            DarkArchiveReader* _parent;
            // TAR mode
            TarReader.EntryRange _tarRange;
            bool _isTar;
        }

        private size_t _zipIdx;
        private size_t _zipLen;

        static EntryIterator makeZip(DarkArchiveReader* parent) {
            EntryIterator it;
            it._parent = parent;
            it._zipIdx = 0;
            it._zipLen = parent._zip.length;
            return it;
        }

        static EntryIterator makeTar(DarkArchiveReader* parent) {
            EntryIterator it;
            it._parent = parent;
            it._tarRange = parent._tar.entries();
            it._isTar = true;
            return it;
        }

        bool empty() {
            if (_isTar)
                return _tarRange.empty();
            return _zipIdx >= _zipLen;
        }

        DarkArchiveEntry front() {
            if (_isTar)
                return _tarRange.front();
            // Update parent's index so readAll() reads the right entry
            _parent._zipIndex = _zipIdx;
            return _parent._zip.entryAt(_zipIdx);
        }

        void popFront() {
            if (_isTar) {
                _tarRange.popFront();
            } else {
                _zipIdx++;
            }
        }
    }
}


// ---------------------------------------------------------------------------
// DarkArchiveWriter
// ---------------------------------------------------------------------------

/// High-level archive writer. Format selected by extension or explicit enum.
struct DarkArchiveWriter {
    private {
        ZipWriter* _zip;
        TarWriter* _tar;
        DarkArchiveFormat _format;
        string _filePath;     // null for memory writer
        bool _finished;
    }

    @disable this();

    /// Create writer with format auto-detected from file extension.
    this(in Path path) {
        this(path.toString());
    }

    /// ditto
    this(string path) {
        _filePath = path;
        auto ext = path.toLower();
        if (ext.endsWith(".zip"))
            _format = DarkArchiveFormat.zip;
        else if (ext.endsWith(".tar.gz") || ext.endsWith(".tgz"))
            _format = DarkArchiveFormat.tarGz;
        else if (ext.endsWith(".tar"))
            _format = DarkArchiveFormat.tar;
        else
            throw new DarkArchiveException("Cannot detect format from extension: " ~ path);
        createWriter();
    }

    /// Create writer with explicit format, writing to file.
    this(in Path path, DarkArchiveFormat fmt) {
        this(path.toString(), fmt);
    }

    /// ditto
    this(string path, DarkArchiveFormat fmt) {
        _filePath = path;
        _format = fmt;
        createWriter();
    }

    /// Create a streaming writer that pipes output to a sink delegate.
    ///
    /// The sink receives raw or compressed output chunks as the archive is
    /// built. `finish()` must be called explicitly — the destructor will not
    /// auto-finish sink-backed writers (unlike file-backed writers, where
    /// `finish()` is called automatically on destruction).
    ///
    /// Only TAR and TAR.GZ are supported. ZIP is not yet supported.
    /// Check `supports(fmt, streamingWrite)` before calling if unsure.
    this(DarkArchiveFormat fmt, void delegate(const(ubyte)[]) sink) {
        _format = fmt;
        final switch (fmt) {
            case DarkArchiveFormat.zip:
                throw new DarkArchiveException(
                    "ZIP does not support streaming write — use supports() to check first");
            case DarkArchiveFormat.tar:
                _tar = new TarWriter();
                *_tar = TarWriter.createToSink(sink);
                break;
            case DarkArchiveFormat.tarGz:
                _tar = new TarWriter();
                *_tar = createGzipTarWriterToSink(sink);
                break;
        }
    }

    private void createWriter() {
        if (_filePath is null)
            throw new DarkArchiveException(
                "DarkArchiveWriter requires a file path — in-memory mode has been removed");

        // File-backed: stream directly to disk
        final switch (_format) {
            case DarkArchiveFormat.zip:
                _zip = new ZipWriter();
                *_zip = ZipWriter.createToFile(_filePath);
                break;
            case DarkArchiveFormat.tar:
                _tar = new TarWriter();
                *_tar = TarWriter.createToFile(_filePath);
                break;
            case DarkArchiveFormat.tarGz:
                // Pipe tar output through streaming gzip compressor
                // directly to the output file. No temp files.
                _tar = new TarWriter();
                *_tar = createGzipTarWriter(_filePath);
                break;
        }
    }

    /// Add file from disk.
    ref DarkArchiveWriter add(in Path sourcePath, string archiveName = null) return {
        return add(sourcePath.toString(), archiveName);
    }

    /// ditto
    ref DarkArchiveWriter add(string sourcePath, string archiveName = null) return {
        import std.file : getSize;
        import std.stdio : File;
        if (archiveName is null)
            archiveName = Path(sourcePath).baseName;
        auto fileSize = getSize(sourcePath);
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
    ///
    /// By default, symlinks are followed and the target content is archived
    /// as a regular file. Use `FollowSymlinks.no` to preserve symlinks as
    /// symlink entries in the archive (Posix only — throws on Windows).
    ref DarkArchiveWriter addTree(in Path rootPath, string prefix = null,
                                   FollowSymlinks followSym = FollowSymlinks.yes) return {
        return addTree(rootPath.toString(), prefix, followSym);
    }

    /// ditto
    ref DarkArchiveWriter addTree(string rootPath, string prefix = null,
                                   FollowSymlinks followSym = FollowSymlinks.yes) return {
        import std.file : dirEntries, SpanMode, isDir, isFile;

        auto root = Path(rootPath);
        if (prefix is null)
            prefix = root.baseName;

        foreach (de; dirEntries(rootPath, SpanMode.depth)) {
            auto relPath = Path(de.name).relativeTo(root);
            auto archName = prefix ~ "/" ~ relPath;

            version(Posix) {
                import std.file : isSymlink, readLink;
                if (de.isSymlink) {
                    if (followSym == FollowSymlinks.no) {
                        // Preserve symlink as symlink entry
                        auto target = readLink(de.name);
                        addSymlink(archName, target);
                    } else {
                        // Follow symlink — archive target content as regular file
                        if (de.isDir) {
                            addDirectory(archName);
                        } else {
                            add(de.name, archName);
                        }
                    }
                    continue;
                }
            } else {
                // On Windows: FollowSymlinks.no is not supported
                if (followSym == FollowSymlinks.no) {
                    throw new DarkArchiveException(
                        "FollowSymlinks.no is not supported on this platform");
                }
            }

            if (de.isDir) {
                addDirectory(archName);
            } else if (de.isFile) {
                add(de.name, archName);
            }
        }

        return this;
    }

    /// Add from in-memory buffer.
    ref DarkArchiveWriter addBuffer(string archiveName, const(ubyte)[] data,
                                     uint permissions = octal!644) return {
        if (_zip !is null)
            _zip.addBuffer(archiveName, data, permissions);
        else
            _tar.addBuffer(archiveName, data, permissions);
        return this;
    }

    /// Add empty directory.
    ref DarkArchiveWriter addDirectory(string archiveName,
                                        uint permissions = octal!755) return {
        if (_zip !is null)
            _zip.addDirectory(archiveName, permissions);
        else
            _tar.addDirectory(archiveName, permissions);
        return this;
    }

    /// Add from streaming source.
    ref DarkArchiveWriter addStream(string archiveName,
                                     scope void delegate(scope void delegate(const(ubyte)[])) reader,
                                     long size = -1,
                                     uint permissions = octal!644) return {
        if (_zip !is null)
            _zip.addStream(archiveName, reader, size, permissions);
        else
            _tar.addStream(archiveName, reader, size, permissions);
        return this;
    }

    /// Add symlink entry.
    /// For TAR: stored as a symlink entry (typeflag '2').
    /// For ZIP: stored as a file whose content is the target path, with
    /// Unix symlink mode in external attributes.
    ref DarkArchiveWriter addSymlink(string archiveName, string target) return {
        if (_tar !is null)
            _tar.addSymlink(archiveName, target);
        else if (_zip !is null)
            _zip.addSymlink(archiveName, target);
        return this;
    }

    /// Finish writing the archive.
    void finish() {
        if (_finished) return;
        _finished = true;

        if (_zip !is null)
            _zip.finish();
        else if (_tar !is null)
            _tar.finish();
    }


    ~this() {
        if (!_finished && _filePath !is null) {
            try { finish(); } catch (Exception) {}
        }
    }
}


// ===========================================================================
// Unit tests — high-level API integration tests
// ===========================================================================

version(unittest) {

    private immutable testDataDir = "test-data";

    /// Read zip via high-level API
    @("high-level: read zip and verify content")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        auto reader = DarkArchiveReader(Path(testDataDir, "test-zip.zip"));
        reader.format.shouldEqual(DarkArchiveFormat.zip);
        string[] names;
        foreach (entry; reader.entries) {
            names ~= entry.pathname;
            if (entry.pathname == "file1.txt")
                reader.readText().shouldEqual("Hello from file1\n");
            else
                reader.skipData();
        }
        assert(names.length > 0);
    }

    /// Read tar.gz via high-level API
    @("high-level: read tar.gz and verify content")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        auto reader = DarkArchiveReader(Path(testDataDir, "test.tar.gz"));
        reader.format.shouldEqual(DarkArchiveFormat.tarGz);
        foreach (entry; reader.entries) {
            if (entry.pathname == "./file1.txt")
                reader.readText().shouldEqual("Hello from file1\n");
            else
                reader.skipData();
        }
    }

    // -------------------------------------------------------------------
    // ArchiveCapability / supports()
    // -------------------------------------------------------------------

    @("capability: ZIP supports randomAccessRead only")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        supports(DarkArchiveFormat.zip, ArchiveCapability.randomAccessRead).shouldBeTrue;
        supports(DarkArchiveFormat.zip, ArchiveCapability.streamingRead).shouldBeFalse;
        supports(DarkArchiveFormat.zip, ArchiveCapability.streamingWrite).shouldBeFalse;
    }

    @("capability: TAR supports streaming read and write")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        supports(DarkArchiveFormat.tar, ArchiveCapability.streamingRead).shouldBeTrue;
        supports(DarkArchiveFormat.tar, ArchiveCapability.streamingWrite).shouldBeTrue;
        supports(DarkArchiveFormat.tar, ArchiveCapability.randomAccessRead).shouldBeFalse;
    }

    @("capability: TAR.GZ supports streaming read and write")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        supports(DarkArchiveFormat.tarGz, ArchiveCapability.streamingRead).shouldBeTrue;
        supports(DarkArchiveFormat.tarGz, ArchiveCapability.streamingWrite).shouldBeTrue;
        supports(DarkArchiveFormat.tarGz, ArchiveCapability.randomAccessRead).shouldBeFalse;
    }

    @("capability: format property feeds supports() naturally")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        auto reader = DarkArchiveReader(Path(testDataDir, "test-zip.zip"));
        scope(exit) reader.close();
        reader.format.supports(ArchiveCapability.randomAccessRead).shouldBeTrue;
        reader.format.supports(ArchiveCapability.streamingRead).shouldBeFalse;
    }

    /// Write zip round-trip via high-level API
    @("high-level: write zip round-trip")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : remove, exists;

        auto outPath = Path(testDataDir, "test-hl-write.zip");

        DarkArchiveWriter(outPath)
            .addBuffer("hello.txt", cast(const(ubyte)[]) "Hello World!")
            .addDirectory("emptydir")
            .finish();

        auto reader = DarkArchiveReader(outPath);
        scope(exit) {
            reader.close();
            if (exists(outPath.toString)) remove(outPath.toString);
        }

        bool foundHello;
        foreach (entry; reader.entries) {
            if (entry.pathname == "hello.txt") {
                foundHello = true;
                reader.readText().shouldEqual("Hello World!");
            } else {
                reader.skipData();
            }
        }
        foundHello.shouldBeTrue;
    }

    /// Write tar.gz round-trip
    @("high-level: write tar.gz round-trip")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : remove, exists;

        auto outPath = Path(testDataDir, "test-hl-write.tar.gz");

        DarkArchiveWriter(outPath, DarkArchiveFormat.tarGz)
            .addBuffer("file-a.txt", cast(const(ubyte)[]) "Content A")
            .addBuffer("file-b.txt", cast(const(ubyte)[]) "Content B")
            .finish();

        auto reader = DarkArchiveReader(outPath);
        scope(exit) {
            reader.close();
            if (exists(outPath.toString)) remove(outPath.toString);
        }

        int count;
        foreach (entry; reader.entries) {
            count++;
            if (entry.pathname == "file-a.txt")
                reader.readText().shouldEqual("Content A");
            else if (entry.pathname == "file-b.txt")
                reader.readText().shouldEqual("Content B");
            else
                reader.skipData();
        }
        count.shouldEqual(2);
    }

    /// Cross-format — same data readable from zip and tar.gz
    @("high-level: cross-format round-trip")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : remove, exists;

        auto zipPath = Path(testDataDir, "test-hl-cross.zip");
        auto tarPath = Path(testDataDir, "test-hl-cross.tar.gz");
        scope(exit) {
            if (exists(zipPath.toString)) remove(zipPath.toString);
            if (exists(tarPath.toString)) remove(tarPath.toString);
        }

        auto content = cast(const(ubyte)[]) "Cross-format test";

        DarkArchiveWriter(zipPath)
            .addBuffer("cross.txt", content)
            .finish();

        DarkArchiveWriter(tarPath, DarkArchiveFormat.tarGz)
            .addBuffer("cross.txt", content)
            .finish();

        // Read zip
        auto r1 = DarkArchiveReader(zipPath);
        scope(exit) r1.close();
        foreach (e; r1.entries) {
            if (e.pathname == "cross.txt")
                r1.readText().shouldEqual("Cross-format test");
            else
                r1.skipData();
        }

        // Read tar.gz
        auto r2 = DarkArchiveReader(tarPath);
        scope(exit) r2.close();
        foreach (e; r2.entries) {
            if (e.pathname == "cross.txt")
                r2.readText().shouldEqual("Cross-format test");
            else
                r2.skipData();
        }
    }

    /// Error handling — non-existent file
    @("high-level: non-existent file throws")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        bool caught;
        try {
            auto reader = DarkArchiveReader(Path("nonexistent-file.zip"));
        } catch (Exception e) {
            caught = true;
        }
        caught.shouldBeTrue;
    }

    /// Extract to directory
    @("high-level: extractTo")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, readText, rmdirRecurse;

        auto extractDir = Path(testDataDir, "extract-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(Path(testDataDir, "test-zip.zip"));
        scope(exit) reader.close();
        reader.extractTo(extractDir);

        assert(exists((extractDir ~ "file1.txt").toString));
        readText((extractDir ~ "file1.txt").toString).shouldEqual("Hello from file1\n");
        assert(exists((extractDir ~ "subdir/nested.txt").toString));
        readText((extractDir ~ "subdir/nested.txt").toString).shouldEqual("Nested file content\n");
    }

    /// Write to file, read back
    @("high-level: write to file, read back")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, remove;
        auto tmpPath = "test-data/test-hl-mem.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        DarkArchiveWriter(tmpPath, DarkArchiveFormat.zip)
            .addBuffer("mem.txt", cast(const(ubyte)[]) "from memory")
            .finish();

        auto reader = DarkArchiveReader(tmpPath);
        scope(exit) reader.close();
        foreach (entry; reader.entries) {
            if (entry.pathname == "mem.txt")
                reader.readText().shouldEqual("from memory");
            else
                reader.skipData();
        }
    }

    /// Method chaining
    @("high-level: method chaining")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, remove;
        auto tmpPath = "test-data/test-hl-chain.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        DarkArchiveWriter(tmpPath, DarkArchiveFormat.zip)
            .addBuffer("a.txt", cast(const(ubyte)[]) "A")
            .addBuffer("b.txt", cast(const(ubyte)[]) "B")
            .addBuffer("c.txt", cast(const(ubyte)[]) "C")
            .finish();

        auto reader = DarkArchiveReader(tmpPath);
        scope(exit) reader.close();
        int count;
        foreach (entry; reader.entries) {
            count++;
            reader.skipData();
        }
        count.shouldEqual(3);
    }

    // -------------------------------------------------------------------
    // Security tests — extraction path traversal and symlink escape
    // -------------------------------------------------------------------

    /// Path traversal: entry with "../" must be rejected by extractTo
    @("security: extractTo rejects path with '..' components")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, remove;

        auto tmpPath = "test-data/test-sec-dotdot.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        DarkArchiveWriter(tmpPath, DarkArchiveFormat.zip)
            .addBuffer("../escape.txt", cast(const(ubyte)[]) "escaped!")
            .finish();

        auto extractDir = Path(testDataDir, "sec-dotdot-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(tmpPath);
        scope(exit) reader.close();
        bool caught;
        try {
            reader.extractTo(extractDir);
        } catch (DarkArchiveException e) {
            caught = true;
        }
        caught.shouldBeTrue;
        // The escaped file must NOT exist outside extract dir
        assert(!exists(Path(testDataDir, "escape.txt").toString),
            "file must not be created outside extraction directory");
    }

    /// Path traversal: entry with "foo/../../escape.txt" must be rejected
    @("security: extractTo rejects nested '..' traversal")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, remove;

        auto tmpPath = "test-data/test-sec-nested-dotdot.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        DarkArchiveWriter(tmpPath, DarkArchiveFormat.zip)
            .addBuffer("foo/../../escape2.txt", cast(const(ubyte)[]) "escaped!")
            .finish();

        auto extractDir = Path(testDataDir, "sec-nested-dotdot-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(tmpPath);
        scope(exit) reader.close();
        bool caught;
        try {
            reader.extractTo(extractDir);
        } catch (DarkArchiveException e) {
            caught = true;
        }
        caught.shouldBeTrue;
    }

    /// Path traversal: absolute path must be rejected
    @("security: extractTo rejects absolute paths")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, remove;

        auto tmpPath = "test-data/test-sec-abs.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        DarkArchiveWriter(tmpPath, DarkArchiveFormat.zip)
            .addBuffer("/tmp/evil.txt", cast(const(ubyte)[]) "evil!")
            .finish();

        auto extractDir = Path(testDataDir, "sec-abs-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(tmpPath);
        scope(exit) reader.close();
        bool caught;
        try {
            reader.extractTo(extractDir);
        } catch (DarkArchiveException e) {
            caught = true;
        }
        caught.shouldBeTrue;
    }

    /// Symlink with absolute target: skipped by default (no symlinks flag)
    @("security: extractTo skips symlink with absolute target by default")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, remove;
        import darkarchive.formats.tar : TarWriter;

        auto tmpTar = "test-data/test-sec-symlink-abs.tar";
        scope(exit) if (exists(tmpTar)) remove(tmpTar);
        auto tw = TarWriter.createToFile(tmpTar);
        scope(exit) tw.close();
        tw.addSymlink("evil-link", "/etc/passwd");
        tw.finish();

        auto extractDir = Path(testDataDir, "sec-symlink-abs-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        // With defaults (no symlinks flag), symlink is silently skipped
        auto reader = DarkArchiveReader(tmpTar);
        scope(exit) reader.close();
        reader.extractTo(extractDir);
        assert(!exists((extractDir ~ "evil-link").toString),
            "symlink must not be created without symlinks flag");
    }

    /// Symlink with absolute target: rejected when symlinks flag IS set
    version(Posix) @("security: extractTo rejects absolute symlink when symlinks enabled")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, remove;
        import darkarchive.formats.tar : TarWriter;

        auto tmpTar = "test-data/test-sec-symlink-abs-en.tar";
        scope(exit) if (exists(tmpTar)) remove(tmpTar);

        auto tw = TarWriter.createToFile(tmpTar);
        scope(exit) tw.close();
        tw.addSymlink("evil-link", "/etc/passwd");
        tw.finish();

        auto extractDir = Path(testDataDir, "sec-symlink-abs-enabled-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(tmpTar);
        scope(exit) reader.close();
        bool caught;
        try {
            reader.extractTo(extractDir,
                DarkExtractFlags.defaults | DarkExtractFlags.symlinks);
        } catch (DarkArchiveException e) {
            caught = true;
        }
        caught.shouldBeTrue;
    }

    /// Symlink with traversal target: skipped by default
    @("security: extractTo skips symlink with traversal target by default")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, remove;
        import darkarchive.formats.tar : TarWriter;

        auto tmpTar = "test-data/test-sec-symlink-trav.tar";
        scope(exit) if (exists(tmpTar)) remove(tmpTar);

        auto tw = TarWriter.createToFile(tmpTar);
        scope(exit) tw.close();
        tw.addSymlink("escape-link", "../../../../etc/shadow");
        tw.finish();

        auto extractDir = Path(testDataDir, "sec-symlink-trav-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(tmpTar);
        scope(exit) reader.close();
        reader.extractTo(extractDir);
        assert(!exists((extractDir ~ "escape-link").toString),
            "symlink must not be created without symlinks flag");
    }

    /// Symlink with traversal target: rejected when symlinks flag IS set
    version(Posix) @("security: extractTo rejects traversal symlink when symlinks enabled")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, remove;
        import darkarchive.formats.tar : TarWriter;

        auto tmpTar = "test-data/test-sec-symlink-trav-en.tar";
        scope(exit) if (exists(tmpTar)) remove(tmpTar);

        auto tw = TarWriter.createToFile(tmpTar);
        scope(exit) tw.close();
        tw.addSymlink("escape-link", "../../../../etc/shadow");
        tw.finish();

        auto extractDir = Path(testDataDir, "sec-symlink-trav-enabled-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(tmpTar);
        scope(exit) reader.close();
        bool caught;
        try {
            reader.extractTo(extractDir,
                DarkExtractFlags.defaults | DarkExtractFlags.symlinks);
        } catch (DarkArchiveException e) {
            caught = true;
        }
        caught.shouldBeTrue;
    }

    /// Entry name "." and ".." as standalone components
    @("security: extractTo rejects entry named '..'")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, remove;

        auto tmpPath = "test-data/test-sec-dotdot-name.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        DarkArchiveWriter(tmpPath, DarkArchiveFormat.zip)
            .addBuffer("..", cast(const(ubyte)[]) "dot dot")
            .finish();

        auto extractDir = Path(testDataDir, "sec-dotdot-name-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(tmpPath);
        scope(exit) reader.close();
        bool caught;
        try {
            reader.extractTo(extractDir);
        } catch (DarkArchiveException e) {
            caught = true;
        }
        caught.shouldBeTrue;
    }

    // -------------------------------------------------------------------
    // CVE-inspired tests
    // -------------------------------------------------------------------

    /// CVE-2021-20206 pattern: Two-step symlink+file extraction escape.
    /// With defaults (no symlinks flag), symlinks are skipped — attack is moot.
    @("CVE: two-step symlink+file — safe by default (symlinks skipped)")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, remove;
        import darkarchive.formats.tar : TarWriter;

        auto tmpTar = "test-data/test-cve-twostep.tar";
        scope(exit) if (exists(tmpTar)) remove(tmpTar);

        auto tw = TarWriter.createToFile(tmpTar);
        scope(exit) tw.close();
        tw.addSymlink("escape-dir", "/tmp");
        tw.addBuffer("escape-dir/pwned.txt", cast(const(ubyte)[]) "pwned!");
        tw.finish();

        auto extractDir = Path(testDataDir, "sec-twostep-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        // With defaults, symlink is skipped, "escape-dir/pwned.txt" written
        // as a regular file under extractDir (no symlink to follow)
        auto reader = DarkArchiveReader(tmpTar);
        scope(exit) reader.close();
        reader.extractTo(extractDir);
        assert(!exists("/tmp/pwned.txt"),
            "file must not be written to /tmp/pwned.txt");
    }

    /// CVE-2021-20206: With symlinks enabled, absolute target is still rejected
    version(Posix) @("CVE: two-step symlink+file — absolute target rejected with symlinks enabled")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, remove;
        import darkarchive.formats.tar : TarWriter;

        auto tmpTar = "test-data/test-cve-twostep-en.tar";
        scope(exit) if (exists(tmpTar)) remove(tmpTar);

        auto tw = TarWriter.createToFile(tmpTar);
        scope(exit) tw.close();
        tw.addSymlink("escape-dir", "/tmp");
        tw.addBuffer("escape-dir/pwned.txt", cast(const(ubyte)[]) "pwned!");
        tw.finish();

        auto extractDir = Path(testDataDir, "sec-twostep-enabled-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(tmpTar);
        scope(exit) reader.close();
        bool caught;
        try {
            reader.extractTo(extractDir,
                DarkExtractFlags.defaults | DarkExtractFlags.symlinks);
        } catch (DarkArchiveException e) {
            caught = true;
        }
        caught.shouldBeTrue;
        assert(!exists("/tmp/pwned.txt"));
    }

    /// CVE-2021-20206 variant: relative symlink escape — safe by default
    @("CVE: two-step relative symlink — safe by default (symlinks skipped)")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, remove;
        import darkarchive.formats.tar : TarWriter;

        auto tmpTar = "test-data/test-cve-twostep-rel.tar";
        scope(exit) if (exists(tmpTar)) remove(tmpTar);

        auto tw = TarWriter.createToFile(tmpTar);
        scope(exit) tw.close();
        tw.addSymlink("linkdir", "../../");
        tw.addBuffer("linkdir/escape.txt", cast(const(ubyte)[]) "escaped!");
        tw.finish();

        auto extractDir = Path(testDataDir, "sec-twostep-rel-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(tmpTar);
        scope(exit) reader.close();
        reader.extractTo(extractDir);
        assert(!exists(Path(testDataDir, "escape.txt").toString),
            "file must not be created outside extract dir");
    }

    /// CVE-2021-20206 relative: with symlinks enabled, traversal target rejected
    version(Posix) @("CVE: two-step relative symlink — rejected with symlinks enabled")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, remove;
        import darkarchive.formats.tar : TarWriter;

        auto tmpTar = "test-data/test-cve-twostep-rel-en.tar";
        scope(exit) if (exists(tmpTar)) remove(tmpTar);

        auto tw = TarWriter.createToFile(tmpTar);
        scope(exit) tw.close();
        tw.addSymlink("linkdir", "../../");
        tw.addBuffer("linkdir/escape.txt", cast(const(ubyte)[]) "escaped!");
        tw.finish();

        auto extractDir = Path(testDataDir, "sec-twostep-rel-en-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(tmpTar);
        scope(exit) reader.close();
        bool caught;
        try {
            reader.extractTo(extractDir,
                DarkExtractFlags.defaults | DarkExtractFlags.symlinks);
        } catch (DarkArchiveException e) {
            caught = true;
        }
        caught.shouldBeTrue;
    }

    /// CVE-2018-1002200 "Zip Slip" — verify ".." check is per-component,
    /// not substring match. "file..name.txt" is a legitimate filename.
    @("CVE: Zip Slip - file..name.txt is legitimate, not rejected")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, remove;

        auto tmpPath = "test-data/test-cve-legit-dotdot.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        DarkArchiveWriter(tmpPath, DarkArchiveFormat.zip)
            .addBuffer("file..name.txt", cast(const(ubyte)[]) "legitimate")
            .finish();

        auto extractDir = Path(testDataDir, "sec-legit-dotdot-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        // This should NOT throw — "file..name.txt" has ".." in the name
        // but not as a path component
        auto reader = DarkArchiveReader(tmpPath);
        scope(exit) reader.close();
        reader.extractTo(extractDir);

        assert(exists((extractDir ~ "file..name.txt").toString),
            "file..name.txt should be extracted successfully");
    }

    /// CVE-2023-39804 pattern: pax path attribute overrides ustar name with traversal.
    /// ustar header has clean name, but pax path = "../../evil.txt"
    @("CVE: pax path override with traversal")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, remove;
        import darkarchive.formats.tar : TarWriter;

        auto tmpTar = "test-data/test-cve-pax-trav.tar";
        scope(exit) if (exists(tmpTar)) remove(tmpTar);

        auto tw = TarWriter.createToFile(tmpTar);
        scope(exit) tw.close();
        tw.addBuffer("../../pax-evil.txt", cast(const(ubyte)[]) "pax attack");
        tw.finish();

        auto extractDir = Path(testDataDir, "sec-pax-trav-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(tmpTar);
        scope(exit) reader.close();
        bool caught;
        try {
            reader.extractTo(extractDir);
        } catch (DarkArchiveException e) {
            caught = true;
        }
        caught.shouldBeTrue;
    }

    /// Without symlinks flag, symlinks are skipped regardless of target
    @("security: absolute symlink skipped with DarkExtractFlags.none")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, remove;
        import darkarchive.formats.tar : TarWriter;

        auto tmpTar = "test-data/test-sec-abs-sym-uncond.tar";
        scope(exit) if (exists(tmpTar)) remove(tmpTar);

        auto tw = TarWriter.createToFile(tmpTar);
        scope(exit) tw.close();
        tw.addSymlink("danger", "/etc/passwd");
        tw.finish();

        auto extractDir = Path(testDataDir, "sec-abs-sym-unconditional");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        // Without symlinks flag, symlink is silently skipped — no error, no symlink
        auto reader = DarkArchiveReader(tmpTar);
        scope(exit) reader.close();
        reader.extractTo(extractDir, DarkExtractFlags.none);
        assert(!exists((extractDir ~ "danger").toString),
            "symlink must not be created without symlinks flag");
    }

    /// With symlinks flag but no securePaths, absolute symlink is still rejected
    version(Posix) @("security: absolute symlink rejected unconditionally with symlinks flag")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, remove;
        import darkarchive.formats.tar : TarWriter;

        auto tmpTar = "test-data/test-sec-abs-sym-flag.tar";
        scope(exit) if (exists(tmpTar)) remove(tmpTar);

        auto tw = TarWriter.createToFile(tmpTar);
        scope(exit) tw.close();
        tw.addSymlink("danger", "/etc/passwd");
        tw.finish();

        auto extractDir = Path(testDataDir, "sec-abs-sym-flag-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(tmpTar);
        scope(exit) reader.close();
        bool caught;
        try {
            // symlinks enabled, but no securePaths — absolute still rejected
            reader.extractTo(extractDir, DarkExtractFlags.symlinks);
        } catch (DarkArchiveException e) {
            caught = true;
        }
        caught.shouldBeTrue;
    }

    // -------------------------------------------------------------------
    // Symlink opt-in tests
    // -------------------------------------------------------------------

    /// By default (no symlinks flag), symlink entries are skipped during extraction
    @("security: symlinks skipped by default during extraction")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, isSymlink, remove;
        import darkarchive.formats.tar : TarWriter;

        auto tmpTar = "test-data/test-sec-sym-skip.tar";
        scope(exit) if (exists(tmpTar)) remove(tmpTar);

        auto tw = TarWriter.createToFile(tmpTar);
        scope(exit) tw.close();
        tw.addBuffer("real-file.txt", cast(const(ubyte)[]) "I exist");
        tw.addSymlink("safe-link", "real-file.txt");
        tw.finish();

        auto extractDir = Path(testDataDir, "sec-sym-skip-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(tmpTar);
        scope(exit) reader.close();
        reader.extractTo(extractDir); // defaults — no symlinks flag

        // The regular file must exist
        assert(exists((extractDir ~ "real-file.txt").toString),
            "real-file.txt must be extracted");
        // The symlink must NOT exist — skipped
        assert(!exists((extractDir ~ "safe-link").toString),
            "symlink must be skipped when symlinks flag is not set");
    }

    /// With symlinks flag, safe relative symlinks are created
    version(Posix) @("security: symlinks created when flag is set")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, isSymlink, readText, remove;
        import darkarchive.formats.tar : TarWriter;

        auto tmpTar = "test-data/test-sec-sym-create.tar";
        scope(exit) if (exists(tmpTar)) remove(tmpTar);

        auto tw = TarWriter.createToFile(tmpTar);
        scope(exit) tw.close();
        tw.addBuffer("target.txt", cast(const(ubyte)[]) "target content");
        tw.addSymlink("link.txt", "target.txt");
        tw.finish();

        auto extractDir = Path(testDataDir, "sec-sym-create-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(tmpTar);
        scope(exit) reader.close();
        reader.extractTo(extractDir,
            DarkExtractFlags.defaults | DarkExtractFlags.symlinks);

        // Both must exist
        assert(exists((extractDir ~ "target.txt").toString));
        assert(exists((extractDir ~ "link.txt").toString));
        // The symlink must actually be a symlink
        assert(isSymlink((extractDir ~ "link.txt").toString));
        // Reading through the symlink must give target content
        readText((extractDir ~ "link.txt").toString).shouldEqual("target content");
    }

    /// With symlinks flag, absolute targets are still rejected
    version(Posix) @("security: absolute symlink still rejected even with symlinks flag")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, remove;
        import darkarchive.formats.tar : TarWriter;

        auto tmpTar = "test-data/test-sec-sym-abs-flag.tar";
        scope(exit) if (exists(tmpTar)) remove(tmpTar);

        auto tw = TarWriter.createToFile(tmpTar);
        scope(exit) tw.close();
        tw.addSymlink("evil", "/etc/passwd");
        tw.finish();

        auto extractDir = Path(testDataDir, "sec-sym-abs-flag-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(tmpTar);
        scope(exit) reader.close();
        bool caught;
        try {
            reader.extractTo(extractDir,
                DarkExtractFlags.defaults | DarkExtractFlags.symlinks);
        } catch (DarkArchiveException e) {
            caught = true;
        }
        caught.shouldBeTrue;
    }

    // -------------------------------------------------------------------
    // Creative attack vector tests
    // -------------------------------------------------------------------

    /// Null byte in filename — OS truncates at null, writing to wrong path.
    /// "innocent.txt\x00../../etc/passwd" → OS sees "innocent.txt"
    /// But the entry claims a different name. Must not cause confusion.
    @("attack: null byte in filename")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, remove;

        auto tmpPath = "test-data/test-atk-null-byte.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        DarkArchiveWriter(tmpPath, DarkArchiveFormat.zip)
            .addBuffer("safe.txt\x00hidden", cast(const(ubyte)[]) "trick")
            .finish();

        auto extractDir = Path(testDataDir, "sec-null-byte-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(tmpPath);
        scope(exit) reader.close();
        reader.extractTo(extractDir);

        // The file should be created, but with the FULL name (D strings
        // include bytes after null). However, the filesystem may truncate.
        // The key assertion: no file created at unexpected location.
        assert(!exists((extractDir ~ "hidden").toString),
            "null byte must not create file at truncated-suffix path");
    }

    /// Filename "." (current directory) — must not overwrite extraction root.
    /// extractTo strips "./" prefix, leaving empty path, which is skipped.
    @("attack: filename is just '.'")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, remove, dirEntries, SpanMode;

        auto tmpPath = "test-data/test-atk-dot-name.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        DarkArchiveWriter(tmpPath, DarkArchiveFormat.zip)
            .addBuffer(".", cast(const(ubyte)[]) "overwrite root?")
            .finish();

        auto extractDir = Path(testDataDir, "sec-dot-name-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(tmpPath);
        scope(exit) reader.close();
        try {
            reader.extractTo(extractDir);
        } catch (Exception) {
            // May throw — acceptable
        }

        // Entry must be iterable with correct name
        auto reader2 = DarkArchiveReader(tmpPath);
        scope(exit) reader2.close();
        int count;
        foreach (entry; reader2.entries) {
            count++;
            entry.pathname.shouldEqual(".");
        }
        count.shouldEqual(1);
    }

    /// Duplicate filenames — second entry overwrites first. Library should
    /// not crash. Both entries should be readable during iteration.
    @("attack: duplicate filenames in archive")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, readText;

        // Create ZIP with duplicate names (Python-generated test data exists)
        auto extractDir = Path(testDataDir, "sec-dupe-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(
            Path(testDataDir, "test-duplicate-names.zip"));
        scope(exit) reader.close();

        // Should not crash during extraction
        reader.extractTo(extractDir);

        // File should exist (second entry wins)
        assert(exists((extractDir ~ "dupe.txt").toString));
        auto content = readText((extractDir ~ "dupe.txt").toString);
        // Content should be from one of the entries (second overwrites first)
        assert(content == "first version\n" || content == "second version\n",
            "dupe.txt should contain content from one of the entries");
    }

    /// Very long pathname (>1000 chars) — entry must be iterable and
    /// content readable even if filesystem rejects extraction.
    @("attack: very long pathname")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, remove;
        import std.array : replicate;

        // 50-char segments * 20 levels = 1000+ char path
        auto segments = "abcdefghijklmnopqrstuvwxyz01234567890123456789abcd/";
        auto longPath = segments.replicate(20) ~ "file.txt";

        auto tmpPath = "test-data/test-atk-longpath.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        DarkArchiveWriter(tmpPath, DarkArchiveFormat.zip)
            .addBuffer(longPath, cast(const(ubyte)[]) "deep")
            .finish();

        // Entry must be iterable with correct name and content
        auto reader = DarkArchiveReader(tmpPath);
        scope(exit) reader.close();
        string foundName;
        string foundContent;
        reader.processEntries(
            (const ref entry, scope dataReader) {
                foundName = entry.pathname;
                foundContent = dataReader.readText();
            });
        foundName.shouldEqual(longPath);
        foundContent.shouldEqual("deep");
    }

    /// Control characters in filename (newlines, tabs)
    @("attack: control characters in filename")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, remove;

        auto tmpPath = "test-data/test-atk-ctrl-char.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        DarkArchiveWriter(tmpPath, DarkArchiveFormat.zip)
            .addBuffer("line1\nline2.txt", cast(const(ubyte)[]) "newline name")
            .addBuffer("tab\there.txt", cast(const(ubyte)[]) "tab name")
            .finish();

        auto extractDir = Path(testDataDir, "sec-control-char-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        // Should not crash. Filesystem may accept or reject these names.
        auto reader1 = DarkArchiveReader(tmpPath);
        scope(exit) reader1.close();
        try {
            reader1.extractTo(extractDir);
        } catch (Exception) {
            // Some filesystems reject control chars — acceptable
        }

        // Entry iteration must work regardless
        auto reader2 = DarkArchiveReader(tmpPath);
        scope(exit) reader2.close();
        int count;
        foreach (entry; reader2.entries) {
            count++;
            assert(entry.pathname.length > 0);
        }
        count.shouldEqual(2);
    }

    /// Right-to-Left Override (U+202E) in filename — visual spoofing attack.
    /// "readme\u202Etxt.exe" displays as "readmeexe.txt" in some terminals.
    /// Library should not crash; ideally entries are still iterable.
    @("attack: RTL override in filename")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, remove;

        auto tmpPath = "test-data/test-atk-rtl.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        DarkArchiveWriter(tmpPath, DarkArchiveFormat.zip)
            .addBuffer("readme\xE2\x80\xAEtxt.exe",
                cast(const(ubyte)[]) "spoofed extension")
            .finish();

        // Must not crash during reading
        auto reader = DarkArchiveReader(tmpPath);
        scope(exit) reader.close();
        int count;
        foreach (entry; reader.entries) {
            count++;
            assert(entry.pathname.length > 0);
        }
        count.shouldEqual(1);
    }

    /// Zip bomb: high compression ratio — small compressed, huge decompressed.
    /// Library must not allocate unbounded memory.
    @("attack: deflate bomb (high compression ratio)")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, remove;
        import darkarchive.formats.zip.writer : ZipWriter;
        import darkarchive.formats.zip.reader : ZipReader;

        // Create data that compresses extremely well: 1MB of zeros
        auto zeros = new ubyte[](1024 * 1024);

        auto tmpPath = "test-data/test-atk-bomb.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        auto writer = ZipWriter.createToFile(tmpPath);
        scope(exit) writer.close();
        writer.addBuffer("bomb.bin", zeros);
        writer.finish();

        // The compressed size should be tiny compared to uncompressed
        auto reader = ZipReader(tmpPath);
        scope(exit) reader.close();
        assert(reader.length == 1);

        // Reading should work — 1MB is reasonable
        auto content = reader.readData(0);
        content.length.shouldEqual(1024 * 1024);

        // Verify it's all zeros
        foreach (b; content)
            assert(b == 0);
    }

    /// Overlapping entries: two central dir entries pointing to same local
    /// header — amplification attack. Reading both should not crash.
    @("attack: overlapping central directory entries")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import darkarchive.formats.zip.writer : ZipWriter;
        import darkarchive.formats.zip.reader : ZipReader;

        // We can't easily craft overlapping entries with ZipWriter.
        // But we can verify that reading duplicate-named entries from
        // test-duplicate-names.zip doesn't cause issues.
        auto reader = ZipReader(testDataDir ~ "/test-duplicate-names.zip");
        assert(reader.length >= 2);

        // Read all entries — must not crash
        foreach (i; 0 .. reader.length) {
            auto data = reader.readData(i);
            assert(data !is null);
        }
    }

    /// File and directory with same name — what happens?
    @("attack: file and directory with same name")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, remove;

        auto tmpPath = "test-data/test-atk-conflict.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        // Write a directory, then a file with same name (without trailing /)
        DarkArchiveWriter(tmpPath, DarkArchiveFormat.zip)
            .addDirectory("conflict")
            .addBuffer("conflict", cast(const(ubyte)[]) "file wins?")
            .finish();

        auto extractDir = Path(testDataDir, "sec-conflict-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        // Should not crash. Result is implementation-defined.
        auto reader = DarkArchiveReader(tmpPath);
        scope(exit) reader.close();
        try {
            reader.extractTo(extractDir);
        } catch (Exception) {
            // May fail — that's acceptable
        }
    }

    /// Windows-style path with colon — NTFS alternate data stream attack.
    /// "file.txt:hidden" on Windows writes to ADS. On Linux it's a valid filename.
    @("attack: colon in filename (NTFS ADS)")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, remove;

        auto tmpPath = "test-data/test-atk-colon.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        DarkArchiveWriter(tmpPath, DarkArchiveFormat.zip)
            .addBuffer("file.txt:hidden", cast(const(ubyte)[]) "ADS data")
            .finish();

        // Must not crash during reading
        auto reader = DarkArchiveReader(tmpPath);
        scope(exit) reader.close();
        int count;
        foreach (entry; reader.entries) {
            count++;
            assert(entry.pathname == "file.txt:hidden");
        }
        count.shouldEqual(1);
    }

    // -------------------------------------------------------------------
    // processEntries tests
    // -------------------------------------------------------------------

    /// processEntries on ZIP — find specific entry and read content
    @("processEntries: ZIP find and read specific entry")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, remove;

        auto tmpPath = "test-data/test-pe-zip-find.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        DarkArchiveWriter(tmpPath, DarkArchiveFormat.zip)
            .addBuffer("a.txt", cast(const(ubyte)[]) "content A")
            .addBuffer("b.txt", cast(const(ubyte)[]) "content B")
            .addBuffer("c.txt", cast(const(ubyte)[]) "content C")
            .finish();

        auto reader = DarkArchiveReader(tmpPath);
        scope(exit) reader.close();
        string found;
        auto count = reader.processEntries(["b.txt"],
            (const ref entry, scope dataReader) {
                found = dataReader.readText();
            });

        count.shouldEqual(1);
        found.shouldEqual("content B");
    }

    /// processEntries on TAR — sequential find
    @("processEntries: TAR find and read specific entry")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, remove;
        import darkarchive.formats.tar : TarWriter;

        auto tmpTar = "test-data/test-pe-tar-find.tar";
        scope(exit) if (exists(tmpTar)) remove(tmpTar);
        auto tw = TarWriter.createToFile(tmpTar);
        scope(exit) tw.close();
        tw.addBuffer("first.txt", cast(const(ubyte)[]) "first");
        tw.addBuffer("second.txt", cast(const(ubyte)[]) "second");
        tw.addBuffer("third.txt", cast(const(ubyte)[]) "third");
        tw.finish();

        auto reader = DarkArchiveReader(tmpTar);
        scope(exit) reader.close();
        string found;
        auto count = reader.processEntries(["second.txt"],
            (const ref entry, scope dataReader) {
                found = dataReader.readText();
            });

        count.shouldEqual(1);
        found.shouldEqual("second");
    }

    /// processEntries — returns 0 when no match, delegate never called
    @("processEntries: returns 0 when no match")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, remove;

        auto tmpPath = "test-data/test-pe-no-match.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        DarkArchiveWriter(tmpPath, DarkArchiveFormat.zip)
            .addBuffer("exists.txt", cast(const(ubyte)[]) "data")
            .finish();

        auto reader = DarkArchiveReader(tmpPath);
        scope(exit) reader.close();
        bool delegateCalled;
        auto count = reader.processEntries(["nonexistent.txt"],
            (const ref entry, scope dataReader) {
                delegateCalled = true;
            });

        count.shouldEqual(0);
        delegateCalled.shouldBeFalse;
    }

    /// processEntries — multiple entries, all found
    @("processEntries: multiple entries all found")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, remove;

        auto tmpPath = "test-data/test-pe-multi-found.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        DarkArchiveWriter(tmpPath, DarkArchiveFormat.zip)
            .addBuffer("x.txt", cast(const(ubyte)[]) "X")
            .addBuffer("y.txt", cast(const(ubyte)[]) "Y")
            .addBuffer("z.txt", cast(const(ubyte)[]) "Z")
            .finish();

        auto reader = DarkArchiveReader(tmpPath);
        scope(exit) reader.close();
        string[] found;
        auto count = reader.processEntries(["z.txt", "x.txt"],
            (const ref entry, scope dataReader) {
                found ~= dataReader.readText();
            });

        count.shouldEqual(2);
        import std.algorithm : canFind;
        assert(found.canFind("X"));
        assert(found.canFind("Z"));
    }

    /// processEntries on TAR.GZ — works through gzip layer
    @("processEntries: TAR.GZ through gzip layer")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : remove, exists;

        auto tmpTarGz = "test-data/test-pe-targz.tar.gz";
        scope(exit) if (exists(tmpTarGz)) remove(tmpTarGz);
        DarkArchiveWriter(tmpTarGz, DarkArchiveFormat.tarGz)
            .addBuffer("gz-file.txt", cast(const(ubyte)[]) "gzipped content")
            .finish();

        auto reader = DarkArchiveReader(tmpTarGz);
        scope(exit) reader.close();
        string found;
        auto count = reader.processEntries(["gz-file.txt"],
            (const ref entry, scope dataReader) {
                found = dataReader.readText();
            });

        count.shouldEqual(1);
        found.shouldEqual("gzipped content");
    }

    /// processEntries all-entries overload — delegate called for every entry
    @("processEntries: all-entries overload")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, remove;

        auto tmpPath = "test-data/test-pe-all-entries.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        DarkArchiveWriter(tmpPath, DarkArchiveFormat.zip)
            .addBuffer("one.txt", cast(const(ubyte)[]) "1")
            .addBuffer("two.txt", cast(const(ubyte)[]) "2")
            .addBuffer("three.txt", cast(const(ubyte)[]) "3")
            .finish();

        auto reader = DarkArchiveReader(tmpPath);
        scope(exit) reader.close();
        int count;
        reader.processEntries(
            (const ref entry, scope dataReader) {
                count++;
            });

        count.shouldEqual(3);
    }

    /// processEntries — delegate reads data via readAll
    @("processEntries: delegate reads binary data via readAll")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, remove;

        auto testData = new ubyte[](1024);
        foreach (i, ref b; testData) b = cast(ubyte)(i & 0xFF);

        auto tmpPath = "test-data/test-pe-binary.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        DarkArchiveWriter(tmpPath, DarkArchiveFormat.zip)
            .addBuffer("binary.bin", testData)
            .finish();

        auto reader = DarkArchiveReader(tmpPath);
        scope(exit) reader.close();
        ubyte[] found;
        reader.processEntries(["binary.bin"],
            (const ref entry, scope dataReader) {
                found = dataReader.readAll();
            });

        found.length.shouldEqual(1024);
        found.shouldEqual(testData);
    }

    /// processEntries with real test-data archives
    @("processEntries: real test-zip.zip")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        auto reader = DarkArchiveReader(Path(testDataDir, "test-zip.zip"));
        string content;
        auto count = reader.processEntries(["file1.txt"],
            (const ref entry, scope dataReader) {
                content = dataReader.readText();
            });
        count.shouldEqual(1);
        content.shouldEqual("Hello from file1\n");
    }

    /// processEntries with real tar.gz
    @("processEntries: real test.tar.gz")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        auto reader = DarkArchiveReader(Path(testDataDir, "test.tar.gz"));
        string content;
        auto count = reader.processEntries(["./file2.txt"],
            (const ref entry, scope dataReader) {
                content = dataReader.readText();
            });
        count.shouldEqual(1);
        content.shouldEqual("Hello from file2\n");
    }

    /// processEntries — read data in chunks without loading full entry
    @("processEntries: chunked read avoids full memory load")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, remove;

        // Create entry with 32KB of data
        auto testData = new ubyte[](32768);
        foreach (i, ref b; testData) b = cast(ubyte)(i & 0xFF);

        auto tmpPath = "test-data/test-pe-chunked.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        DarkArchiveWriter(tmpPath, DarkArchiveFormat.zip)
            .addBuffer("large.bin", testData)
            .finish();

        auto reader = DarkArchiveReader(tmpPath);
        scope(exit) reader.close();
        size_t totalBytes;
        size_t chunkCount;
        reader.processEntries(["large.bin"],
            (const ref entry, scope dataReader) {
                // Read in chunks — no single 32KB allocation
                dataReader.readChunks((const(ubyte)[] chunk) {
                    totalBytes += chunk.length;
                    chunkCount++;
                    assert(chunk.length > 0);
                    assert(chunk.length <= 8192); // each chunk <= 8KB
                });
            });

        totalBytes.shouldEqual(32768);
        assert(chunkCount >= 4, "should have multiple chunks for 32KB data");
    }

    /// processEntries — chunked read on TAR works
    @("processEntries: chunked read on TAR")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, remove;
        import darkarchive.formats.tar : TarWriter;

        auto testData = new ubyte[](16384);
        foreach (i, ref b; testData) b = cast(ubyte)(i & 0xFF);

        auto tmpTar = "test-data/test-pe-chunked-tar.tar";
        scope(exit) if (exists(tmpTar)) remove(tmpTar);
        auto tw = TarWriter.createToFile(tmpTar);
        scope(exit) tw.close();
        tw.addBuffer("tardata.bin", testData);
        tw.finish();

        auto reader = DarkArchiveReader(tmpTar);
        scope(exit) reader.close();
        size_t totalBytes;
        reader.processEntries(["tardata.bin"],
            (const ref entry, scope dataReader) {
                dataReader.readChunks((const(ubyte)[] chunk) {
                    totalBytes += chunk.length;
                });
            });

        totalBytes.shouldEqual(16384);
    }

    /// processEntries — extractTo uses chunked writes (not readAll)
    @("processEntries: extractTo uses streaming write")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, readText, getSize, remove;

        // Create archive with a 64KB entry
        auto testData = new ubyte[](65536);
        foreach (i, ref b; testData) b = cast(ubyte)(i & 0xFF);

        auto tmpPath = "test-data/test-pe-streaming.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        DarkArchiveWriter(tmpPath, DarkArchiveFormat.zip)
            .addBuffer("big.bin", testData)
            .finish();

        auto extractDir = Path(testDataDir, "streaming-extract-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(tmpPath);
        scope(exit) reader.close();
        reader.extractTo(extractDir);

        // Verify file was written correctly
        auto extractedPath = (extractDir ~ "big.bin").toString;
        assert(exists(extractedPath));
        getSize(extractedPath).shouldEqual(65536);
    }

    /// processEntries — chunked read on empty entry produces no chunks
    @("processEntries: chunked read on empty entry")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, remove;

        auto tmpPath = "test-data/test-pe-empty.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        DarkArchiveWriter(tmpPath, DarkArchiveFormat.zip)
            .addBuffer("empty.txt", cast(const(ubyte)[]) "")
            .finish();

        auto reader = DarkArchiveReader(tmpPath);
        scope(exit) reader.close();
        int chunkCount;
        reader.processEntries(["empty.txt"],
            (const ref entry, scope dataReader) {
                dataReader.readChunks((const(ubyte)[] chunk) {
                    chunkCount++;
                });
            });

        chunkCount.shouldEqual(0);
    }

    // -------------------------------------------------------------------
    // extractTo with delegate tests
    // -------------------------------------------------------------------

    /// Strip prefix — delegate removes "odoo-18.0/" from destPath
    @("extractTo delegate: strip prefix (unfoldPath)")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, readText, remove;

        auto tmpPath = "test-data/test-dlg-unfold.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        DarkArchiveWriter(tmpPath, DarkArchiveFormat.zip)
            .addBuffer("odoo-18.0/README.txt", cast(const(ubyte)[]) "readme")
            .addBuffer("odoo-18.0/setup.py", cast(const(ubyte)[]) "setup")
            .addDirectory("odoo-18.0/addons")
            .finish();

        auto extractDir = Path(testDataDir, "unfold-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(tmpPath);
        scope(exit) reader.close();
        reader.extractTo(extractDir, DarkExtractFlags.defaults,
            (ref params) {
                import std.algorithm : startsWith;
                if (params.destPath.startsWith("odoo-18.0/"))
                    params.destPath = params.destPath["odoo-18.0/".length .. $];
                return true;
            });

        assert(exists((extractDir ~ "README.txt").toString),
            "README.txt should be at root, not under odoo-18.0/");
        readText((extractDir ~ "README.txt").toString).shouldEqual("readme");
        assert(exists((extractDir ~ "setup.py").toString));
        assert(!exists((extractDir ~ "odoo-18.0").toString),
            "odoo-18.0/ prefix should be stripped");
    }

    /// Skip by extension — delegate returns false for .pyc
    @("extractTo delegate: skip .pyc files")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, remove;
        import std.algorithm : endsWith;

        auto tmpPath = "test-data/test-dlg-skip-pyc.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        DarkArchiveWriter(tmpPath, DarkArchiveFormat.zip)
            .addBuffer("module.py", cast(const(ubyte)[]) "python source")
            .addBuffer("module.pyc", cast(const(ubyte)[]) "bytecode")
            .addBuffer("other.txt", cast(const(ubyte)[]) "text")
            .finish();

        auto extractDir = Path(testDataDir, "skip-pyc-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(tmpPath);
        scope(exit) reader.close();
        reader.extractTo(extractDir, DarkExtractFlags.defaults,
            (ref params) {
                return !params.destPath.endsWith(".pyc");
            });

        assert(exists((extractDir ~ "module.py").toString));
        assert(exists((extractDir ~ "other.txt").toString));
        assert(!exists((extractDir ~ "module.pyc").toString),
            ".pyc should be skipped");
    }

    /// Security after delegate — delegate adds "../", exception thrown
    @("extractTo delegate: security catches delegate-introduced traversal")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, remove;

        auto tmpPath = "test-data/test-dlg-sec-trav.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        DarkArchiveWriter(tmpPath, DarkArchiveFormat.zip)
            .addBuffer("safe.txt", cast(const(ubyte)[]) "data")
            .finish();

        auto extractDir = Path(testDataDir, "delegate-sec-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(tmpPath);
        scope(exit) reader.close();
        bool caught;
        try {
            reader.extractTo(extractDir, DarkExtractFlags.defaults,
                (ref params) {
                    params.destPath = "../escape.txt";
                    return true;
                });
        } catch (DarkArchiveException e) {
            caught = true;
        }
        caught.shouldBeTrue;
    }

    /// Delegate introduces absolute path — exception thrown
    @("extractTo delegate: security catches delegate-introduced absolute path")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, remove;

        auto tmpPath = "test-data/test-dlg-sec-abs.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        DarkArchiveWriter(tmpPath, DarkArchiveFormat.zip)
            .addBuffer("safe.txt", cast(const(ubyte)[]) "data")
            .finish();

        auto extractDir = Path(testDataDir, "delegate-abs-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(tmpPath);
        scope(exit) reader.close();
        bool caught;
        try {
            reader.extractTo(extractDir, DarkExtractFlags.defaults,
                (ref params) {
                    params.destPath = "/tmp/evil.txt";
                    return true;
                });
        } catch (DarkArchiveException e) {
            caught = true;
        }
        caught.shouldBeTrue;
    }

    /// Null delegate — same as no-delegate overload
    @("extractTo delegate: null delegate same as default")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, readText, remove;

        auto tmpPath = "test-data/test-dlg-null.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        DarkArchiveWriter(tmpPath, DarkArchiveFormat.zip)
            .addBuffer("test.txt", cast(const(ubyte)[]) "content")
            .finish();

        auto extractDir = Path(testDataDir, "null-delegate-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(tmpPath);
        scope(exit) reader.close();
        reader.extractTo(extractDir, DarkExtractFlags.defaults, null);

        assert(exists((extractDir ~ "test.txt").toString));
        readText((extractDir ~ "test.txt").toString).shouldEqual("content");
    }

    /// Skip all entries — empty extraction dir
    @("extractTo delegate: skip all entries")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, dirEntries, SpanMode, remove;

        auto tmpPath = "test-data/test-dlg-skip-all.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        DarkArchiveWriter(tmpPath, DarkArchiveFormat.zip)
            .addBuffer("a.txt", cast(const(ubyte)[]) "A")
            .addBuffer("b.txt", cast(const(ubyte)[]) "B")
            .finish();

        auto extractDir = Path(testDataDir, "skip-all-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(tmpPath);
        scope(exit) reader.close();
        reader.extractTo(extractDir, DarkExtractFlags.defaults,
            (ref params) { return false; });

        // Directory might not even be created, or should be empty
        if (exists(extractDir.toString)) {
            int fileCount;
            foreach (de; dirEntries(extractDir.toString, SpanMode.depth))
                fileCount++;
            fileCount.shouldEqual(0);
        }
    }

    /// Backward compatibility — existing extractTo still works
    @("extractTo delegate: backward compatibility")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, readText, remove;

        auto tmpPath = "test-data/test-dlg-compat.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        DarkArchiveWriter(tmpPath, DarkArchiveFormat.zip)
            .addBuffer("compat.txt", cast(const(ubyte)[]) "works")
            .finish();

        // No-delegate overload
        auto extractDir1 = Path(testDataDir, "compat-test-1");
        scope(exit) if (exists(extractDir1.toString)) rmdirRecurse(extractDir1.toString);
        auto reader1 = DarkArchiveReader(tmpPath);
        scope(exit) reader1.close();
        reader1.extractTo(extractDir1);

        readText((extractDir1 ~ "compat.txt").toString).shouldEqual("works");

        // Flags-only overload
        auto extractDir2 = Path(testDataDir, "compat-test-2");
        scope(exit) if (exists(extractDir2.toString)) rmdirRecurse(extractDir2.toString);

        auto reader2 = DarkArchiveReader(tmpPath);
        scope(exit) reader2.close();
        reader2.extractTo(extractDir2, DarkExtractFlags.defaults);
        readText((extractDir2 ~ "compat.txt").toString).shouldEqual("works");
    }

    /// Delegate can read sourceEntry metadata
    @("extractTo delegate: read sourceEntry metadata")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, remove;

        auto tmpPath = "test-data/test-dlg-metadata.zip";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        DarkArchiveWriter(tmpPath, DarkArchiveFormat.zip)
            .addBuffer("file.txt", cast(const(ubyte)[]) "content")
            .addDirectory("dir")
            .finish();

        auto extractDir = Path(testDataDir, "source-entry-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        bool sawFile, sawDir;
        auto reader = DarkArchiveReader(tmpPath);
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

    /// extractTo delegate on TAR.GZ
    @("extractTo delegate: works on TAR.GZ")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, readText, remove;

        auto tmpTarGz = "test-data/test-dlg-targz.tar.gz";
        scope(exit) if (exists(tmpTarGz)) remove(tmpTarGz);
        DarkArchiveWriter(tmpTarGz, DarkArchiveFormat.tarGz)
            .addBuffer("prefix/data.txt", cast(const(ubyte)[]) "tar data")
            .finish();

        auto extractDir = Path(testDataDir, "delegate-targz-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(tmpTarGz);
        scope(exit) reader.close();
        reader.extractTo(extractDir, DarkExtractFlags.defaults,
            (ref params) {
                import std.algorithm : startsWith;
                if (params.destPath.startsWith("prefix/"))
                    params.destPath = params.destPath["prefix/".length .. $];
                return true;
            });

        assert(exists((extractDir ~ "data.txt").toString));
        readText((extractDir ~ "data.txt").toString).shouldEqual("tar data");
    }

    // -------------------------------------------------------------------
    // addTree symlink following tests
    // -------------------------------------------------------------------

    /// addTree follows symlinks by default — archives target content
    @("addTree: follows symlinks by default")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        version(Posix) {
            import std.file : exists, rmdirRecurse, mkdirRecurse, write,
                symlink, readText, getcwd, remove;

            auto srcDir = Path(getcwd(), testDataDir, "symlink-follow-src");
            scope(exit) if (exists(srcDir.toString)) rmdirRecurse(srcDir.toString);
            mkdirRecurse(srcDir.toString);
            write((srcDir ~ "real.txt").toString, "real content");
            symlink("real.txt", (srcDir ~ "link.txt").toString);

            // Archive with default (follow symlinks)
            auto tmpZip = "test-data/test-tree-follow-sym.zip";
            scope(exit) if (exists(tmpZip)) remove(tmpZip);

            DarkArchiveWriter(tmpZip, DarkArchiveFormat.zip)
                .addTree(srcDir)
                .finish();

            // Read back — link.txt should be a regular file with real content
            auto reader = DarkArchiveReader(tmpZip);
            scope(exit) reader.close();
            bool foundLink;
            foreach (entry; reader.entries) {
                import std.algorithm : endsWith;
                if (entry.pathname.endsWith("link.txt")) {
                    foundLink = true;
                    entry.isFile.shouldBeTrue;
                    entry.isSymlink.shouldBeFalse;
                }
            }
            foundLink.shouldBeTrue;
        }
    }

    /// addTree with FollowSymlinks.no preserves symlinks (Posix only)
    @("addTree: FollowSymlinks.no preserves symlinks")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        version(Posix) {
            import std.file : exists, rmdirRecurse, mkdirRecurse, write,
                symlink, getcwd, remove;

            auto srcDir = Path(getcwd(), testDataDir, "symlink-preserve-src");
            scope(exit) if (exists(srcDir.toString)) rmdirRecurse(srcDir.toString);
            mkdirRecurse(srcDir.toString);
            write((srcDir ~ "target.txt").toString, "target content");
            symlink("target.txt", (srcDir ~ "preserved.txt").toString);

            auto tmpTar = "test-data/test-tree-preserve-sym.tar";
            scope(exit) if (exists(tmpTar)) remove(tmpTar);

            DarkArchiveWriter(tmpTar, DarkArchiveFormat.tar)
                .addTree(srcDir, null, FollowSymlinks.no)
                .finish();

            auto reader = DarkArchiveReader(tmpTar);
            scope(exit) reader.close();
            bool foundSymlink;
            foreach (entry; reader.entries) {
                import std.algorithm : endsWith;
                if (entry.pathname.endsWith("preserved.txt")) {
                    foundSymlink = true;
                    entry.isSymlink.shouldBeTrue;
                    entry.symlinkTarget.shouldEqual("target.txt");
                }
            }
            foundSymlink.shouldBeTrue;
        }
    }

    /// addTree default on directory with no symlinks — works same as before
    @("addTree: no symlinks in source works normally")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, mkdirRecurse, write, getcwd, remove;

        auto srcDir = Path(getcwd(), testDataDir, "nosym-tree-src");
        scope(exit) if (exists(srcDir.toString)) rmdirRecurse(srcDir.toString);
        mkdirRecurse((srcDir ~ "sub").toString);
        write((srcDir ~ "a.txt").toString, "aaa");
        write((srcDir ~ "sub/b.txt").toString, "bbb");

        auto tmpZip = "test-data/test-tree-nosym.zip";
        scope(exit) if (exists(tmpZip)) remove(tmpZip);

        DarkArchiveWriter(tmpZip, DarkArchiveFormat.zip)
            .addTree(srcDir)
            .finish();

        auto reader = DarkArchiveReader(tmpZip);
        scope(exit) reader.close();
        int fileCount;
        foreach (entry; reader.entries) {
            if (entry.isFile) fileCount++;
        }
        assert(fileCount >= 2, "should have at least 2 files");
    }

    /// addTree with dangling symlink — must throw (broken source data)
    @("addTree: dangling symlink throws")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        version(Posix) {
            import std.file : exists, rmdirRecurse, mkdirRecurse, write,
                symlink, getcwd, remove;

            auto srcDir = Path(getcwd(), testDataDir, "dangling-sym-src");
            scope(exit) if (exists(srcDir.toString)) rmdirRecurse(srcDir.toString);
            mkdirRecurse(srcDir.toString);
            write((srcDir ~ "real.txt").toString, "real content");
            symlink("nonexistent-target.txt", (srcDir ~ "dangling.txt").toString);

            auto tmpZip = "test-data/test-tree-dangling.zip";
            scope(exit) if (exists(tmpZip)) remove(tmpZip);
            auto writer = DarkArchiveWriter(tmpZip, DarkArchiveFormat.zip);
            bool threw;
            try {
                writer.addTree(srcDir);
            } catch (Exception e) {
                threw = true;
            }
            threw.shouldBeTrue;
        }
    }

    /// addTree with circular symlinks — must throw, not hang
    @("addTree: circular symlinks throw, not hang")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        version(Posix) {
            import std.file : exists, rmdirRecurse, mkdirRecurse, write,
                symlink, getcwd, remove;

            auto srcDir = Path(getcwd(), testDataDir, "circular-sym-src");
            scope(exit) if (exists(srcDir.toString)) rmdirRecurse(srcDir.toString);
            mkdirRecurse(srcDir.toString);
            write((srcDir ~ "real.txt").toString, "real content");
            symlink("circular-b.txt", (srcDir ~ "circular-a.txt").toString);
            symlink("circular-a.txt", (srcDir ~ "circular-b.txt").toString);

            auto tmpZip = "test-data/test-tree-circular.zip";
            scope(exit) if (exists(tmpZip)) remove(tmpZip);
            auto writer = DarkArchiveWriter(tmpZip, DarkArchiveFormat.zip);
            bool threw;
            try {
                writer.addTree(srcDir);
            } catch (Exception e) {
                threw = true;
            }
            threw.shouldBeTrue;
        }
    }

    // -------------------------------------------------------------------
    // Permission tests
    // -------------------------------------------------------------------

    /// extractTo preserves safe permission bits (rwx) by default
    version(Posix) @("extractTo: preserves execute permission by default")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, getAttributes, remove;
        import std.conv : octal;
        import darkarchive.formats.tar : TarWriter;

        auto tmpTar = "test-data/test-perm-exec.tar";
        scope(exit) if (exists(tmpTar)) remove(tmpTar);

        auto tw = TarWriter.createToFile(tmpTar);
        scope(exit) tw.close();
        tw.addBuffer("script.sh", cast(const(ubyte)[]) "#!/bin/sh\necho hello",
            octal!755);
        tw.addBuffer("data.txt", cast(const(ubyte)[]) "just data",
            octal!644);
        tw.finish();

        auto extractDir = Path(testDataDir, "perm-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(tmpTar);
        scope(exit) reader.close();
        reader.extractTo(extractDir);

        // script.sh should have execute bit
        auto scriptAttrs = getAttributes((extractDir ~ "script.sh").toString);
        assert(scriptAttrs & octal!100, "script.sh should have owner execute bit");

        // data.txt should NOT have execute bit
        auto dataAttrs = getAttributes((extractDir ~ "data.txt").toString);
        assert(!(dataAttrs & octal!100), "data.txt should not have execute bit");
    }

    /// extractTo strips dangerous bits (setuid, setgid, sticky)
    version(Posix) @("extractTo: strips setuid/setgid/sticky bits")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, getAttributes, remove;
        import std.conv : octal;
        import darkarchive.formats.tar : TarWriter;

        auto tmpTar = "test-data/test-perm-dangerous.tar";
        scope(exit) if (exists(tmpTar)) remove(tmpTar);

        auto tw = TarWriter.createToFile(tmpTar);
        scope(exit) tw.close();
        // setuid (04755) — dangerous
        tw.addBuffer("setuid.sh", cast(const(ubyte)[]) "#!/bin/sh",
            octal!4755);
        // setgid (02755) — dangerous
        tw.addBuffer("setgid.sh", cast(const(ubyte)[]) "#!/bin/sh",
            octal!2755);
        tw.finish();

        auto extractDir = Path(testDataDir, "perm-dangerous-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(tmpTar);
        scope(exit) reader.close();
        reader.extractTo(extractDir);

        // Execute bit should be preserved, but setuid/setgid stripped
        auto attrs1 = getAttributes((extractDir ~ "setuid.sh").toString);
        assert(attrs1 & octal!100, "should have execute bit");
        assert(!(attrs1 & octal!4000), "setuid must be stripped");

        auto attrs2 = getAttributes((extractDir ~ "setgid.sh").toString);
        assert(attrs2 & octal!100, "should have execute bit");
        assert(!(attrs2 & octal!2000), "setgid must be stripped");
    }

    /// extractTo caps group/other write bits (prevents world-writable files)
    version(Posix) @("extractTo: caps group/other write bits")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, getAttributes, remove;
        import std.conv : octal;
        import darkarchive.formats.tar : TarWriter;

        auto tmpTar = "test-data/test-perm-cap.tar";
        scope(exit) if (exists(tmpTar)) remove(tmpTar);

        auto tw = TarWriter.createToFile(tmpTar);
        scope(exit) tw.close();
        tw.addBuffer("world-writable.txt", cast(const(ubyte)[]) "data",
            octal!666);
        tw.addBuffer("full-perm.sh", cast(const(ubyte)[]) "#!/bin/sh",
            octal!777);
        tw.addBuffer("normal.txt", cast(const(ubyte)[]) "data",
            octal!644);
        tw.addBuffer("owner-only.sh", cast(const(ubyte)[]) "#!/bin/sh",
            octal!700);
        tw.finish();

        auto extractDir = Path(testDataDir, "perm-cap-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(tmpTar);
        scope(exit) reader.close();
        reader.extractTo(extractDir);

        // 0o666 → 0o644 (group/other write stripped)
        auto a1 = getAttributes((extractDir ~ "world-writable.txt").toString);
        assert(!(a1 & octal!20), "group-write must be stripped from 0o666");
        assert(!(a1 & octal!2), "other-write must be stripped from 0o666");
        assert(a1 & octal!400, "owner-read must be preserved");

        // 0o777 → 0o755 (group/other write stripped, execute preserved)
        auto a2 = getAttributes((extractDir ~ "full-perm.sh").toString);
        assert(a2 & octal!100, "owner-execute preserved");
        assert(a2 & octal!10, "group-execute preserved");
        assert(!(a2 & octal!20), "group-write must be stripped from 0o777");
        assert(!(a2 & octal!2), "other-write must be stripped from 0o777");

        // 0o644 → 0o644 (already safe, unchanged)
        auto a3 = getAttributes((extractDir ~ "normal.txt").toString);
        assert(a3 & octal!400, "owner-read preserved");
        assert(!(a3 & octal!100), "no execute on normal file");

        // 0o700 → 0o700 (no group/other bits to strip)
        auto a4 = getAttributes((extractDir ~ "owner-only.sh").toString);
        assert(a4 & octal!100, "owner-execute preserved");
        assert(!(a4 & octal!40), "no group-read");
    }

    // -------------------------------------------------------------------
    // Chunk-based streaming constructors
    // -------------------------------------------------------------------

    @("streaming read: DarkArchiveReader(tarGz, delegate) reads entries correctly")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : read;

        auto compressed = cast(ubyte[]) read(testDataDir ~ "/test.tar.gz");
        auto reader = DarkArchiveReader(DarkArchiveFormat.tarGz, chunkSource(compressed, 4096));
        scope(exit) reader.close();

        reader.format.shouldEqual(DarkArchiveFormat.tarGz);
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

    @("streaming read: DarkArchiveReader(tar, delegate) reads entries correctly")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : read, write, remove, exists;

        // Build a small TAR in memory to use as chunk source
        auto tarPath = testDataDir ~ "/test-stream-src.tar";
        scope(exit) if (exists(tarPath)) remove(tarPath);
        DarkArchiveWriter(tarPath, DarkArchiveFormat.tar)
            .addBuffer("hello.txt", cast(const(ubyte)[]) "stream content")
            .finish();

        auto raw = cast(ubyte[]) read(tarPath);
        auto reader = DarkArchiveReader(DarkArchiveFormat.tar, chunkSource(raw, 512));
        scope(exit) reader.close();

        reader.format.shouldEqual(DarkArchiveFormat.tar);
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

    @("streaming read: DarkArchiveReader(zip, delegate) throws immediately")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;
        bool threw;
        try {
            auto reader = DarkArchiveReader(DarkArchiveFormat.zip, () => cast(ubyte[]) []);
            reader.close();
        } catch (DarkArchiveException) {
            threw = true;
        }
        threw.shouldBeTrue;
    }

    @("streaming write: DarkArchiveWriter(tar, sink) produces readable TAR")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : write, remove, exists;

        ubyte[] buf;
        DarkArchiveWriter(DarkArchiveFormat.tar,
                (const(ubyte)[] chunk) { buf ~= chunk; })
            .addBuffer("hello.txt", cast(const(ubyte)[]) "sink content")
            .finish();

        auto tmpPath = testDataDir ~ "/test-sink-tar.tar";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        write(tmpPath, buf);

        auto reader = DarkArchiveReader(tmpPath);
        scope(exit) reader.close();
        bool found;
        foreach (entry; reader.entries) {
            if (entry.pathname == "hello.txt") {
                found = true;
                reader.readText().shouldEqual("sink content");
            } else {
                reader.skipData();
            }
        }
        found.shouldBeTrue;
    }

    @("streaming write: DarkArchiveWriter(tarGz, sink) produces readable TAR.GZ")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : write, remove, exists;

        ubyte[] buf;
        DarkArchiveWriter(DarkArchiveFormat.tarGz,
                (const(ubyte)[] chunk) { buf ~= chunk; })
            .addBuffer("hello.txt", cast(const(ubyte)[]) "gzip sink content")
            .finish();

        auto tmpPath = testDataDir ~ "/test-sink-tar.tar.gz";
        scope(exit) if (exists(tmpPath)) remove(tmpPath);
        write(tmpPath, buf);

        auto reader = DarkArchiveReader(tmpPath);
        scope(exit) reader.close();
        bool found;
        foreach (entry; reader.entries) {
            if (entry.pathname == "hello.txt") {
                found = true;
                reader.readText().shouldEqual("gzip sink content");
            } else {
                reader.skipData();
            }
        }
        found.shouldBeTrue;
    }

    @("streaming write: DarkArchiveWriter(zip, sink) throws immediately")
    unittest {
        import unit_threaded.assertions : shouldBeTrue;
        bool threw;
        try {
            auto w = DarkArchiveWriter(DarkArchiveFormat.zip,
                (const(ubyte)[]) {});
            w.finish();
        } catch (DarkArchiveException) {
            threw = true;
        }
        threw.shouldBeTrue;
    }

    // -------------------------------------------------------------------
    // Write path memory tests
    // -------------------------------------------------------------------

    /// TAR write to file should not accumulate archive in memory
    @("streaming write: TAR to file does not accumulate memory")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, remove, getSize;
        import core.memory : GC;

        auto outPath = Path(testDataDir, "mem-write-test.tar");
        scope(exit) if (exists(outPath.toString)) remove(outPath.toString);

        auto chunk = new ubyte[](64 * 1024); // 64KB per entry

        GC.collect();
        auto memBefore = GC.stats.usedSize;

        auto writerTar = DarkArchiveWriter(outPath, DarkArchiveFormat.tar);
        foreach (i; 0 .. 64) {
            import std.format : format;
            writerTar.addBuffer("file_%03d.bin".format(i), chunk);
        }
        writerTar.finish();

        GC.collect();
        auto memAfter = GC.stats.usedSize;
        auto growth = memAfter > memBefore ? memAfter - memBefore : 0;

        // 4MB of data written. Memory growth should be << 4MB if streaming.
        // Currently fails because writer holds full archive in _buf.
        assert(growth < 2 * 1024 * 1024,
            "TAR write: memory grew by " ~ formatMemSize(growth)
            ~ " — writer should stream to file");

        assert(exists(outPath.toString));
        assert(getSize(outPath.toString) > 4 * 1024 * 1024);
    }

    /// ZIP write to file should not accumulate archive in memory
    @("streaming write: ZIP to file does not accumulate memory")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, remove, getSize;
        import core.memory : GC;

        auto outPath = Path(testDataDir, "mem-write-test.zip");
        scope(exit) if (exists(outPath.toString)) remove(outPath.toString);

        auto chunk = new ubyte[](64 * 1024);

        GC.collect();
        auto memBefore = GC.stats.usedSize;

        auto writerZip = DarkArchiveWriter(outPath, DarkArchiveFormat.zip);
        foreach (i; 0 .. 64) {
            import std.format : format;
            writerZip.addBuffer("file_%03d.bin".format(i), chunk);
        }
        writerZip.finish();

        GC.collect();
        auto memAfter = GC.stats.usedSize;
        auto growth = memAfter > memBefore ? memAfter - memBefore : 0;

        assert(growth < 2 * 1024 * 1024,
            "ZIP write: memory grew by " ~ formatMemSize(growth)
            ~ " — writer should stream to file");

        assert(exists(outPath.toString));
        assert(getSize(outPath.toString) > 0);
    }

    /// TAR.GZ write to file should not accumulate archive in memory
    @("streaming write: TAR.GZ to file does not accumulate memory")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, remove, getSize;
        import core.memory : GC;

        auto outPath = Path(testDataDir, "mem-write-test.tar.gz");
        scope(exit) if (exists(outPath.toString)) remove(outPath.toString);

        auto chunk = new ubyte[](64 * 1024);

        GC.collect();
        auto memBefore = GC.stats.usedSize;

        auto writerGz = DarkArchiveWriter(outPath, DarkArchiveFormat.tarGz);
        foreach (i; 0 .. 64) {
            import std.format : format;
            writerGz.addBuffer("file_%03d.bin".format(i), chunk);
        }
        writerGz.finish();

        GC.collect();
        auto memAfter = GC.stats.usedSize;
        auto growth = memAfter > memBefore ? memAfter - memBefore : 0;

        assert(growth < 2 * 1024 * 1024,
            "TAR.GZ write: memory grew by " ~ formatMemSize(growth)
            ~ " — writer should stream to file");

        assert(exists(outPath.toString));
        assert(getSize(outPath.toString) > 0);
    }

    /// Written streaming archive should be readable and correct
    @("streaming write: TAR round-trip via streaming write")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, remove;

        auto outPath = Path(testDataDir, "stream-write-roundtrip.tar");
        scope(exit) if (exists(outPath.toString)) remove(outPath.toString);

        DarkArchiveWriter(outPath, DarkArchiveFormat.tar)
            .addBuffer("hello.txt", cast(const(ubyte)[]) "Hello!")
            .addBuffer("world.txt", cast(const(ubyte)[]) "World!")
            .finish();

        auto reader = DarkArchiveReader(outPath);
        scope(exit) reader.close();
        int count;
        foreach (entry; reader.entries) {
            count++;
            if (entry.pathname == "hello.txt")
                reader.readText().shouldEqual("Hello!");
            else if (entry.pathname == "world.txt")
                reader.readText().shouldEqual("World!");
        }
        count.shouldEqual(2);
    }

    // -------------------------------------------------------------------
    // Streaming memory tests — verify constant memory on all layers
    // -------------------------------------------------------------------

    /// addStream with known size must NOT buffer the full entry in memory.
    /// TAR format: header needs size upfront — with known size we can write
    /// header then stream data directly without buffering.
    @("streaming: TAR addStream with known size does not buffer full entry")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, remove, getSize;
        import core.memory : GC;

        auto outPath = "test-data/mem-addstream-tar.tar";
        scope(exit) if (exists(outPath)) remove(outPath);

        enum ENTRY_SIZE = 4 * 1024 * 1024; // 4MB entry
        auto chunk = new ubyte[](8192);
        foreach (i, ref b; chunk) b = cast(ubyte)(i & 0xFF);

        GC.collect();
        auto memBefore = GC.stats.usedSize;

        DarkArchiveWriter(outPath, DarkArchiveFormat.tar)
            .addStream("large.bin", (scope sink) {
                foreach (_; 0 .. ENTRY_SIZE / chunk.length)
                    sink(chunk);
            }, ENTRY_SIZE)
            .finish();

        GC.collect();
        auto memAfter = GC.stats.usedSize;
        auto growth = memAfter > memBefore ? memAfter - memBefore : 0;

        assert(growth < 2 * 1024 * 1024,
            "TAR addStream(known size): memory grew by " ~ formatMemSize(growth)
            ~ " — should stream without buffering");
        assert(getSize(outPath) > ENTRY_SIZE);
    }

    /// addStream with known size must NOT buffer the full entry — ZIP format.
    /// ZIP can use data descriptors (bit 3) to defer CRC32/sizes after data,
    /// enabling true streaming with incremental CRC32 + deflate.
    @("streaming: ZIP addStream with known size does not buffer full entry")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, remove, getSize;
        import core.memory : GC;

        auto outPath = "test-data/mem-addstream-zip.zip";
        scope(exit) if (exists(outPath)) remove(outPath);

        enum ENTRY_SIZE = 4 * 1024 * 1024; // 4MB entry
        auto chunk = new ubyte[](8192);
        foreach (i, ref b; chunk) b = cast(ubyte)(i & 0xFF);

        GC.collect();
        auto memBefore = GC.stats.usedSize;

        DarkArchiveWriter(outPath, DarkArchiveFormat.zip)
            .addStream("large.bin", (scope sink) {
                foreach (_; 0 .. ENTRY_SIZE / chunk.length)
                    sink(chunk);
            }, ENTRY_SIZE)
            .finish();

        GC.collect();
        auto memAfter = GC.stats.usedSize;
        auto growth = memAfter > memBefore ? memAfter - memBefore : 0;

        assert(growth < 2 * 1024 * 1024,
            "ZIP addStream(known size): memory grew by " ~ formatMemSize(growth)
            ~ " — should stream without buffering");
        assert(getSize(outPath) > 0);
    }

    /// add() from disk must NOT read the entire file into memory.
    /// Should stream file chunks to the archive writer.
    @("streaming: add() from disk does not load full file into memory")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, remove, getSize;
        import std.stdio : File;
        import core.memory : GC;

        // Create a 4MB source file
        auto srcPath = "test-data/mem-add-source.bin";
        auto outPath = "test-data/mem-add-output.tar";
        scope(exit) {
            if (exists(srcPath)) remove(srcPath);
            if (exists(outPath)) remove(outPath);
        }

        auto f = File(srcPath, "wb");
        auto chunk = new ubyte[](8192);
        foreach (i, ref b; chunk) b = cast(ubyte)(i & 0xFF);
        foreach (_; 0 .. 512) // 512 * 8KB = 4MB
            f.rawWrite(chunk);
        f.close();

        GC.collect();
        auto memBefore = GC.stats.usedSize;

        DarkArchiveWriter(outPath, DarkArchiveFormat.tar)
            .add(srcPath, "large.bin")
            .finish();

        GC.collect();
        auto memAfter = GC.stats.usedSize;
        auto growth = memAfter > memBefore ? memAfter - memBefore : 0;

        assert(growth < 2 * 1024 * 1024,
            "add() from disk: memory grew by " ~ formatMemSize(growth)
            ~ " — should stream file without loading into memory");
        assert(getSize(outPath) > 4 * 1024 * 1024);
    }

    /// Full pipeline: write large entry then read it back chunked.
    /// Total memory must stay bounded throughout — no single point
    /// buffers the full 4MB entry.
    @("streaming: full write+read pipeline stays constant memory (TAR)")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, remove;
        import core.memory : GC;

        auto outPath = "test-data/mem-pipeline-tar.tar";
        scope(exit) if (exists(outPath)) remove(outPath);

        enum ENTRY_SIZE = 4 * 1024 * 1024;
        auto chunk = new ubyte[](8192);
        foreach (i, ref b; chunk) b = cast(ubyte)(i & 0xFF);

        // Write
        DarkArchiveWriter(outPath, DarkArchiveFormat.tar)
            .addStream("pipeline.bin", (scope sink) {
                foreach (_; 0 .. ENTRY_SIZE / chunk.length)
                    sink(chunk);
            }, ENTRY_SIZE)
            .finish();

        GC.collect();
        auto memBefore = GC.stats.usedSize;

        // Read back chunked
        size_t totalRead;
        auto reader = DarkArchiveReader(outPath);
        scope(exit) reader.close();
        reader.processEntries(["pipeline.bin"],
            (const ref entry, scope dataReader) {
                dataReader.readChunks((const(ubyte)[] c) {
                    totalRead += c.length;
                });
            });

        GC.collect();
        auto memAfter = GC.stats.usedSize;
        auto growth = memAfter > memBefore ? memAfter - memBefore : 0;

        totalRead.shouldEqual(ENTRY_SIZE);
        assert(growth < 2 * 1024 * 1024,
            "read pipeline: memory grew by " ~ formatMemSize(growth)
            ~ " — chunked read should not buffer full entry");
    }

    /// Full pipeline for ZIP: write+read large entry with constant memory
    @("streaming: full write+read pipeline stays constant memory (ZIP)")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, remove;
        import core.memory : GC;

        auto outPath = "test-data/mem-pipeline-zip.zip";
        scope(exit) if (exists(outPath)) remove(outPath);

        enum ENTRY_SIZE = 4 * 1024 * 1024;
        auto chunk = new ubyte[](8192);
        foreach (i, ref b; chunk) b = cast(ubyte)(i & 0xFF);

        // Write
        DarkArchiveWriter(outPath, DarkArchiveFormat.zip)
            .addStream("pipeline.bin", (scope sink) {
                foreach (_; 0 .. ENTRY_SIZE / chunk.length)
                    sink(chunk);
            }, ENTRY_SIZE)
            .finish();

        GC.collect();
        auto memBefore = GC.stats.usedSize;

        // Read back chunked
        size_t totalRead;
        auto reader = DarkArchiveReader(outPath);
        scope(exit) reader.close();
        reader.processEntries(["pipeline.bin"],
            (const ref entry, scope dataReader) {
                dataReader.readChunks((const(ubyte)[] c) {
                    totalRead += c.length;
                });
            });

        GC.collect();
        auto memAfter = GC.stats.usedSize;
        auto growth = memAfter > memBefore ? memAfter - memBefore : 0;

        totalRead.shouldEqual(ENTRY_SIZE);
        assert(growth < 2 * 1024 * 1024,
            "ZIP read pipeline: memory grew by " ~ formatMemSize(growth)
            ~ " — chunked read should not buffer full entry");
    }

    /// Full pipeline for TAR.GZ: write+read large entry with constant memory
    @("streaming: full write+read pipeline stays constant memory (TAR.GZ)")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, remove;
        import core.memory : GC;

        auto outPath = "test-data/mem-pipeline-targz.tar.gz";
        scope(exit) if (exists(outPath)) remove(outPath);

        enum ENTRY_SIZE = 4 * 1024 * 1024;
        auto chunk = new ubyte[](8192);
        foreach (i, ref b; chunk) b = cast(ubyte)(i & 0xFF);

        // Write
        DarkArchiveWriter(outPath, DarkArchiveFormat.tarGz)
            .addStream("pipeline.bin", (scope sink) {
                foreach (_; 0 .. ENTRY_SIZE / chunk.length)
                    sink(chunk);
            }, ENTRY_SIZE)
            .finish();

        GC.collect();
        auto memBefore = GC.stats.usedSize;

        // Read back chunked
        size_t totalRead;
        auto reader = DarkArchiveReader(outPath);
        scope(exit) reader.close();
        reader.processEntries(["pipeline.bin"],
            (const ref entry, scope dataReader) {
                dataReader.readChunks((const(ubyte)[] c) {
                    totalRead += c.length;
                });
            });

        GC.collect();
        auto memAfter = GC.stats.usedSize;
        auto growth = memAfter > memBefore ? memAfter - memBefore : 0;

        totalRead.shouldEqual(ENTRY_SIZE);
        assert(growth < 2 * 1024 * 1024,
            "TAR.GZ read pipeline: memory grew by " ~ formatMemSize(growth)
            ~ " — chunked read should not buffer full entry");
    }

    /// addStream round-trip: data written via streaming must be readable and correct
    @("streaming: addStream round-trip data integrity (TAR)")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, remove;

        auto outPath = "test-data/stream-roundtrip-tar.tar";
        scope(exit) if (exists(outPath)) remove(outPath);

        enum ENTRY_SIZE = 32768; // 32KB — small enough to verify content
        auto sourceData = new ubyte[](ENTRY_SIZE);
        foreach (i, ref b; sourceData) b = cast(ubyte)(i & 0xFF);

        DarkArchiveWriter(outPath, DarkArchiveFormat.tar)
            .addStream("data.bin", (scope sink) {
                // Send in 4KB chunks
                foreach (off; 0 .. ENTRY_SIZE / 4096)
                    sink(sourceData[off * 4096 .. (off + 1) * 4096]);
            }, ENTRY_SIZE)
            .finish();

        // Read back and verify
        auto reader = DarkArchiveReader(outPath);
        scope(exit) reader.close();
        ubyte[] readBack;
        reader.processEntries(["data.bin"],
            (const ref entry, scope dataReader) {
                readBack = dataReader.readAll();
            });

        readBack.length.shouldEqual(ENTRY_SIZE);
        readBack.shouldEqual(sourceData);
    }

    // -------------------------------------------------------------------
    // extractTo: symlinked root (macOS /tmp -> /private/tmp regression)
    // -------------------------------------------------------------------

    /// extractTo must succeed when the extraction root itself is (or is under) a
    /// symlinked directory.  Reproduces the macOS CI failure where
    /// /tmp -> /private/tmp caused verifyPathWithinRoot to reject valid paths.
    version(Posix) @("extractTo: symlinked extraction root resolves correctly")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, rmdirRecurse, remove, readText, symlink, mkdir;

        auto zipPath = "test-data/test-symroot.zip";
        scope(exit) if (exists(zipPath)) remove(zipPath);

        DarkArchiveWriter(zipPath, DarkArchiveFormat.zip)
            .addBuffer("hello.txt", cast(const(ubyte)[]) "hello")
            .finish();

        // real dir + relative symlink pointing to it (mirrors macOS /tmp -> /private/tmp)
        auto realDir = "test-data/symroot-real";
        auto linkDir = "test-data/symroot-link";
        scope(exit) {
            if (exists(realDir)) rmdirRecurse(realDir);
            if (exists(linkDir)) remove(linkDir);
        }
        mkdir(realDir);
        symlink("symroot-real", linkDir);

        auto reader = DarkArchiveReader(zipPath);
        scope(exit) reader.close();

        // Must NOT throw "Refusing to write file: resolved path escapes extraction directory"
        reader.extractTo(Path(linkDir));

        assert(exists(realDir ~ "/hello.txt"), "file must land in the real dir");
        readText(realDir ~ "/hello.txt").shouldEqual("hello");
    }

    /// addStream round-trip data integrity for ZIP
    @("streaming: addStream round-trip data integrity (ZIP)")
    unittest {
        import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;
        import std.file : exists, remove;

        auto outPath = "test-data/stream-roundtrip-zip.zip";
        scope(exit) if (exists(outPath)) remove(outPath);

        enum ENTRY_SIZE = 32768;
        auto sourceData = new ubyte[](ENTRY_SIZE);
        foreach (i, ref b; sourceData) b = cast(ubyte)(i & 0xFF);

        DarkArchiveWriter(outPath, DarkArchiveFormat.zip)
            .addStream("data.bin", (scope sink) {
                foreach (off; 0 .. ENTRY_SIZE / 4096)
                    sink(sourceData[off * 4096 .. (off + 1) * 4096]);
            }, ENTRY_SIZE)
            .finish();

        auto reader = DarkArchiveReader(outPath);
        scope(exit) reader.close();
        ubyte[] readBack;
        reader.processEntries(["data.bin"],
            (const ref entry, scope dataReader) {
                readBack = dataReader.readAll();
            });

        readBack.length.shouldEqual(ENTRY_SIZE);
        readBack.shouldEqual(sourceData);
    }
}

private string formatMemSize(size_t bytes) {
    import std.format : format;
    if (bytes < 1024) return "%d B".format(bytes);
    if (bytes < 1024 * 1024) return "%.1f KB".format(cast(double) bytes / 1024);
    return "%.1f MB".format(cast(double) bytes / (1024 * 1024));
}
