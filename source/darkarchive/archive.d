module darkarchive.archive;

import std.string : fromStringz, toStringz;
import std.format : format;
import std.conv : octal;
import std.typecons : SafeRefCounted, RefCountedAutoInitialize;
import core.stdc.config : c_long;

import darkarchive.lib;
import darkarchive.entry : DarkArchiveEntry;
import darkarchive.exception : DarkArchiveException, enforceArchiveOk;

import thepath : Path;


// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Archive format selection
enum DarkArchiveFormat {
    zip,
    tar,
    pax,
    paxRestricted,
    gnutar,
    ustar,
    v7tar,
    sevenZip,
    cpio,
    cpioNewc,
    cpioOdc,
    cpioBin,
    cpioPwb,
    iso9660,
    ar,
    arBsd,
    arSvr4,
    xar,
    warc,
    shar,
    sharDump,
    mtree,
    mtreeClassic,
    raw,
}

/// Compression filter selection
enum DarkArchiveFilter {
    none,
    gzip,
    bzip2,
    xz,
    lzma,
    zstd,
    lz4,
    lzip,
    lzop,
    compress,
    grzip,
    lrzip,
    uuencode,
    b64encode,
}

/// Extract behavior flags
enum DarkExtractFlags {
    none        = 0,
    owner       = ARCHIVE_EXTRACT_OWNER,
    perm        = ARCHIVE_EXTRACT_PERM,
    time        = ARCHIVE_EXTRACT_TIME,
    securePaths = ARCHIVE_EXTRACT_SECURE_SYMLINKS
                | ARCHIVE_EXTRACT_SECURE_NODOTDOT
                | ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS,
    safeWrites  = ARCHIVE_EXTRACT_SAFE_WRITES,
    defaults    = perm | time | securePaths | safeWrites,
}


// ---------------------------------------------------------------------------
// DarkArchiveReader
// ---------------------------------------------------------------------------

/// High-level archive reader. Uses SafeRefCounted for automatic cleanup.
///
/// Note on non-ASCII pathnames: libarchive converts entry pathnames using the
/// process locale (LC_CTYPE). D's runtime starts with LC_ALL="C", which cannot
/// represent non-ASCII characters — pathnames with UTF-8 characters (e.g.,
/// "café.txt") will be returned as null. To fix this, call
/// `setlocale(LC_CTYPE, "C.UTF-8")` early in your program:
///
/// ---
/// import core.stdc.locale : setlocale, LC_CTYPE;
/// void main() {
///     setlocale(LC_CTYPE, "C.UTF-8");
///     // ... use DarkArchiveReader ...
/// }
/// ---
struct DarkArchiveReader {
    private {
        struct Payload {
            archive* _archive;

            @trusted ~this() {
                if (_archive !is null) {
                    archive_read_close(_archive);
                    archive_read_free(_archive);
                    _archive = null;
                }
            }
        }

        SafeRefCounted!(Payload, RefCountedAutoInitialize.no) _payload;
    }

    @disable this();

    /// Open archive from file path (auto-detect format and compression).
    this(in Path path) @trusted {
        this(path.toString());
    }

    /// ditto
    this(string path) @trusted {
        auto a = createReader();
        auto ret = archive_read_open_filename(a, path.toStringz, 10240);
        if (ret != ARCHIVE_OK) {
            auto msg = getErrorMsg(a);
            archive_read_free(a);
            throw new DarkArchiveException("Cannot open '%s': %s".format(path, msg));
        }
        _payload = typeof(_payload)(Payload(a));
    }

    /// Open from memory buffer.
    this(const(ubyte)[] data) @trusted {
        auto a = createReader();
        auto ret = archive_read_open_memory(a, data.ptr, data.length);
        if (ret != ARCHIVE_OK) {
            auto msg = getErrorMsg(a);
            archive_read_free(a);
            throw new DarkArchiveException("Cannot open from memory: %s".format(msg));
        }
        _payload = typeof(_payload)(Payload(a));
    }

    /// Open from file descriptor.
    this(int fd) @trusted {
        auto a = createReader();
        auto ret = archive_read_open_fd(a, fd, 10240);
        if (ret != ARCHIVE_OK) {
            auto msg = getErrorMsg(a);
            archive_read_free(a);
            throw new DarkArchiveException("Cannot open fd %d: %s".format(fd, msg));
        }
        _payload = typeof(_payload)(Payload(a));
    }

    /// Create and configure a new archive reader with all formats/filters
    /// and UTF-8 header charset (avoids locale-dependent pathname conversion).
    private static archive* createReader() @trusted {
        auto a = archive_read_new();
        if (a is null)
            throw new DarkArchiveException("Failed to create archive reader");
        archive_read_support_filter_all(a);
        archive_read_support_format_all(a);
        archive_read_support_format_raw(a);
        // Tell libarchive to use UTF-8 for header charset conversion.
        // Without this, D programs (which start with LC_ALL="C") would get
        // null pathnames for non-ASCII filenames. This is per-archive, not
        // a global side effect.
        archive_read_set_options(a, "hdrcharset=UTF-8");
        return a;
    }

    private static string getErrorMsg(archive* a) @trusted {
        auto errPtr = archive_error_string(a);
        return errPtr is null ? "unknown error" : errPtr.fromStringz.idup;
    }

    private @trusted archive* handle() {
        return _payload._archive;
    }

    // -- Entry iteration --

    /// Range over entries.
    /// WARNING: The returned range borrows from this reader -- do not escape it
    /// past the reader's lifetime or use it after calling other reader methods.
    auto entries() @trusted {
        return EntryRange(handle);
    }

    private static struct EntryRange {
        private archive* _a;
        private archive_entry* _current;
        private bool _done;

        this(archive* a) @trusted {
            _a = a;
            popFront();
        }

        bool empty() @safe { return _done; }

        DarkArchiveEntry front() @trusted {
            return DarkArchiveEntry.borrow(_current);
        }

        void popFront() @trusted {
            auto r = archive_read_next_header(_a, &_current);
            if (r == ARCHIVE_EOF)
                _done = true;
            else
                enforceArchiveOk(_a, r, "reading next header");
        }
    }

    // -- Data reading --

    /// Read current entry's data as chunks. Each chunk is a newly allocated copy.
    auto readData() @trusted {
        return DataChunkRange(handle);
    }

    private static struct DataChunkRange {
        private archive* _a;
        private const(ubyte)[] _current;
        private bool _done;

        this(archive* a) @trusted {
            _a = a;
            popFront();
        }

        bool empty() @safe { return _done; }
        const(ubyte)[] front() @safe { return _current; }

        void popFront() @trusted {
            ubyte[8192] buf;
            auto n = archive_read_data(_a, buf.ptr, buf.length);
            if (n == 0)
                _done = true;
            else if (n < 0)
                enforceArchiveOk(_a, cast(int) n, "reading data");
            else
                _current = buf[0 .. n].dup;
        }
    }

    /// Zero-copy read: each chunk is valid only until next popFront().
    auto readDataNoCopy() @trusted {
        return NoCopyDataRange(handle);
    }

    private static struct NoCopyDataRange {
        private archive* _a;
        private ubyte[8192] _buf;
        private const(ubyte)[] _current;
        private bool _done;

        this(archive* a) @trusted {
            _a = a;
            popFront();
        }

        bool empty() @safe { return _done; }
        const(ubyte)[] front() @safe { return _current; }

        void popFront() @trusted {
            auto n = archive_read_data(_a, _buf.ptr, _buf.length);
            if (n == 0)
                _done = true;
            else if (n < 0)
                enforceArchiveOk(_a, cast(int) n, "reading data");
            else
                _current = _buf[0 .. n];
        }
    }

    /// Read full entry into memory.
    ubyte[] readAll() @trusted {
        import std.array : appender;
        auto buf = appender!(ubyte[])();
        foreach (chunk; readData())
            buf ~= chunk;
        return buf[];
    }

    /// Read entry as text.
    string readText() @trusted {
        return cast(string) readAll();
    }

    // -- Extraction --

    /// Extract entire archive to directory.
    void extractTo(in Path destination, DarkExtractFlags flags = DarkExtractFlags.defaults) @trusted {
        auto a = handle;
        auto ext = archive_write_disk_new();
        if (ext is null)
            throw new DarkArchiveException("Failed to create disk writer");
        scope(exit) archive_write_free(ext);

        archive_write_disk_set_options(ext, flags);
        archive_write_disk_set_standard_lookup(ext);

        auto destStr = destination.toString();

        archive_entry* entry;
        while (true) {
            auto r = archive_read_next_header(a, &entry);
            if (r == ARCHIVE_EOF)
                break;
            enforceArchiveOk(a, r, "extractTo: reading header");

            // Prepend destination path
            auto origPath = archive_entry_pathname(entry);
            if (origPath !is null) {
                auto newPath = Path(destStr, origPath.fromStringz.idup);
                archive_entry_set_pathname(entry, newPath.toString.toStringz);
            }

            r = archive_write_header(ext, entry);
            enforceArchiveOk(ext, r, "extractTo: writing header");

            if (archive_entry_size(entry) > 0) {
                const(void)* buff;
                size_t len;
                la_int64_t offset;
                while (true) {
                    r = archive_read_data_block(a, &buff, &len, &offset);
                    if (r == ARCHIVE_EOF)
                        break;
                    enforceArchiveOk(a, r, "extractTo: reading data block");
                    auto wr = archive_write_data_block(ext, buff, len, offset);
                    enforceArchiveOk(ext, cast(int) wr, "extractTo: writing data block");
                }
            }

            r = archive_write_finish_entry(ext);
            enforceArchiveOk(ext, r, "extractTo: finishing entry");
        }
    }

    /// Skip current entry's data.
    void skipData() @trusted {
        archive_read_data_skip(handle);
    }

    // -- Finding specific entries ---
    //
    // libarchive is a streaming library -- there is no random-access lookup by
    // entry name. To read a specific file, iterate entries(), compare
    // pathname, and call readAll()/readText() on match (calling
    // skipData() on non-matches):
    //
    //     foreach (entry; reader.entries) {
    //         if (entry.pathname == "manifest.json") {
    //             auto content = reader.readText();
    //             break;
    //         }
    //         reader.skipData();
    //     }
    //
    // Performance notes:
    //  - For zip: skipData() can seek past entries (fast) since zip has a
    //    central directory. But the iteration order is still sequential.
    //  - For tar/tar.gz/tar.zst: must decompress/scan sequentially. Cost is
    //    proportional to the position of the target entry in the archive.
    //  - Tip: when creating archives, write frequently-accessed entries
    //    (e.g., manifests) first to minimize scan time on read.

    // -- Metadata --

    string formatName() @trusted {
        auto p = archive_format_name(handle);
        return p is null ? null : p.fromStringz.idup;
    }

    int formatCode() @trusted {
        return archive_format(handle);
    }

    string filterName() @trusted {
        auto p = archive_filter_name(handle, 0);
        return p is null ? null : p.fromStringz.idup;
    }
}


// ---------------------------------------------------------------------------
// DarkArchiveWriter
// ---------------------------------------------------------------------------

struct DarkArchiveWriter {
    private {
        struct Payload {
            archive* _archive;
            archive_entry* _entry;
            bool _finished;
            ubyte[] _memBuf;
            size_t _memUsed;

            @trusted ~this() { finish(); }

            @trusted void finish() {
                if (!_finished && _archive !is null) {
                    archive_write_close(_archive);
                    archive_write_free(_archive);
                    _archive = null;
                    _finished = true;
                }
                if (_entry !is null) {
                    archive_entry_free(_entry);
                    _entry = null;
                }
            }
        }

        SafeRefCounted!(Payload, RefCountedAutoInitialize.no) _payload;
    }

    @disable this();

    /// Create archive writing to file, format+filter auto-detected from extension.
    this(in Path path) @trusted {
        this(path.toString());
    }

    /// ditto
    this(string path) @trusted {
        auto a = archive_write_new();
        if (a is null)
            throw new DarkArchiveException("Failed to create archive writer");
        auto entry = archive_entry_new();

        auto ret = archive_write_set_format_filter_by_ext(a, path.toStringz);
        if (ret != ARCHIVE_OK) {
            archive_entry_free(entry);
            string errMsg = "unknown error";
            auto errPtr = archive_error_string(a);
            if (errPtr !is null)
                errMsg = errPtr.fromStringz.idup;
            archive_write_free(a);
            throw new DarkArchiveException("Cannot auto-detect format for '%s': %s".format(path, errMsg));
        }

        ret = archive_write_open_filename(a, path.toStringz);
        if (ret != ARCHIVE_OK) {
            archive_entry_free(entry);
            string errMsg = "unknown error";
            auto errPtr = archive_error_string(a);
            if (errPtr !is null)
                errMsg = errPtr.fromStringz.idup;
            archive_write_free(a);
            throw new DarkArchiveException("Cannot open '%s' for writing: %s".format(path, errMsg));
        }

        _payload = typeof(_payload)(Payload(a, entry, false));
    }

    /// Create with explicit format and filter.
    this(in Path path, DarkArchiveFormat fmt, DarkArchiveFilter filter = DarkArchiveFilter.none) @trusted {
        this(path.toString(), fmt, filter);
    }

    /// ditto
    this(string path, DarkArchiveFormat fmt, DarkArchiveFilter filter = DarkArchiveFilter.none) @trusted {
        auto a = archive_write_new();
        if (a is null)
            throw new DarkArchiveException("Failed to create archive writer");
        auto entry = archive_entry_new();

        setFormat(a, fmt);
        setFilter(a, filter);

        auto ret = archive_write_open_filename(a, path.toStringz);
        if (ret != ARCHIVE_OK) {
            archive_entry_free(entry);
            string errMsg = "unknown error";
            auto errPtr = archive_error_string(a);
            if (errPtr !is null)
                errMsg = errPtr.fromStringz.idup;
            archive_write_free(a);
            throw new DarkArchiveException("Cannot open '%s' for writing: %s".format(path, errMsg));
        }

        _payload = typeof(_payload)(Payload(a, entry, false));
    }

    /// Write to file descriptor.
    this(int fd, DarkArchiveFormat fmt, DarkArchiveFilter filter = DarkArchiveFilter.none) @trusted {
        auto a = archive_write_new();
        if (a is null)
            throw new DarkArchiveException("Failed to create archive writer");
        auto entry = archive_entry_new();

        setFormat(a, fmt);
        setFilter(a, filter);

        auto ret = archive_write_open_fd(a, fd);
        if (ret != ARCHIVE_OK) {
            archive_entry_free(entry);
            string errMsg = "unknown error";
            auto errPtr = archive_error_string(a);
            if (errPtr !is null)
                errMsg = errPtr.fromStringz.idup;
            archive_write_free(a);
            throw new DarkArchiveException("Cannot open fd %d for writing: %s".format(fd, errMsg));
        }

        _payload = typeof(_payload)(Payload(a, entry, false));
    }

    /// Write to growing memory buffer. Call finish() then writtenData().
    this(DarkArchiveFormat fmt, DarkArchiveFilter filter = DarkArchiveFilter.none) @trusted {
        auto a = archive_write_new();
        if (a is null)
            throw new DarkArchiveException("Failed to create archive writer");
        auto entry = archive_entry_new();

        setFormat(a, fmt);
        setFilter(a, filter);

        // Allocate a buffer for archive_write_open_memory
        auto bufSize = 1024 * 1024; // 1MB initial
        auto buf = new ubyte[](bufSize);
        size_t used = 0;

        auto p = Payload(a, entry, false, buf, used);

        auto ret = archive_write_open_memory(a, buf.ptr, bufSize, &p._memUsed);
        if (ret != ARCHIVE_OK) {
            archive_entry_free(entry);
            string errMsg = "unknown error";
            auto errPtr = archive_error_string(a);
            if (errPtr !is null)
                errMsg = errPtr.fromStringz.idup;
            archive_write_free(a);
            throw new DarkArchiveException("Cannot open memory writer: %s".format(errMsg));
        }

        _payload = typeof(_payload)(p);
    }

    private @trusted archive* handle() {
        return _payload._archive;
    }

    // -- Adding entries --

    /// Add file from disk.
    ref DarkArchiveWriter add(in Path sourcePath, string archiveName = null) @trusted {
        return add(sourcePath.toString(), archiveName);
    }

    /// ditto
    ref DarkArchiveWriter add(string sourcePath, string archiveName = null) @trusted {
        auto a = handle;
        auto entry = _payload._entry;

        auto disk = archive_read_disk_new();
        if (disk is null)
            throw new DarkArchiveException("Failed to create disk reader");
        scope(exit) archive_read_free(disk);
        archive_read_disk_set_standard_lookup(disk);

        archive_entry_clear(entry);
        archive_entry_copy_sourcepath(entry, sourcePath.toStringz);
        auto r = archive_read_disk_entry_from_file(disk, entry, -1, null);
        enforceArchiveOk(disk, r, "reading file metadata");

        if (archiveName is null) {
            archiveName = Path(sourcePath).baseName;
        }
        archive_entry_set_pathname_utf8(entry, archiveName.toStringz);

        r = archive_write_header(a, entry);
        enforceArchiveOk(a, r, "writing header");

        // Write file data
        if (archive_entry_size(entry) > 0) {
            import std.stdio : File;
            auto f = File(sourcePath, "rb");
            ubyte[8192] buf;
            while (true) {
                auto got = f.rawRead(buf[]);
                if (got.length == 0) break;
                auto written = archive_write_data(a, got.ptr, got.length);
                if (written < 0)
                    enforceArchiveOk(a, cast(int) written, "writing file data");
            }
        }

        archive_write_finish_entry(a);

        return this;
    }

    /// Add directory tree recursively.
    ref DarkArchiveWriter addTree(in Path rootPath, string prefix = null) @trusted {
        return addTree(rootPath.toString(), prefix);
    }

    /// ditto
    ref DarkArchiveWriter addTree(string rootPath, string prefix = null) @trusted {
        import std.file : dirEntries, SpanMode, isDir, isFile, isSymlink, readLink;

        auto root = Path(rootPath);
        if (prefix is null)
            prefix = root.baseName;

        foreach (de; dirEntries(rootPath, SpanMode.depth)) {
            auto relPath = Path(de.name).relativeTo(root);
            auto archName = prefix ~ "/" ~ relPath;

            if (de.isSymlink) {
                auto target = readLink(de.name);
                addSymlink(archName, target);
            } else if (de.isDir) {
                addDirectory(archName);
            } else if (de.isFile) {
                add(de.name, archName);
            }
        }

        return this;
    }

    /// Add from in-memory buffer.
    ref DarkArchiveWriter addBuffer(string archiveName, const(ubyte)[] data,
                                     uint permissions = octal!644) @trusted {
        auto a = handle;
        auto entry = _payload._entry;

        archive_entry_clear(entry);
        archive_entry_set_pathname_utf8(entry, archiveName.toStringz);
        archive_entry_set_size(entry, cast(la_int64_t) data.length);
        archive_entry_set_mode(entry, AE_IFREG | permissions);

        auto r = archive_write_header(a, entry);
        enforceArchiveOk(a, r, "writing header for buffer");

        if (data.length > 0) {
            auto written = archive_write_data(a, data.ptr, data.length);
            if (written < 0)
                enforceArchiveOk(a, cast(int) written, "writing buffer data");
        }

        archive_write_finish_entry(a);

        return this;
    }

    /// Add empty directory.
    ref DarkArchiveWriter addDirectory(string archiveName,
                                        uint permissions = octal!755) @trusted {
        auto a = handle;
        auto entry = _payload._entry;

        // Ensure trailing slash for directory entries
        if (archiveName.length == 0 || archiveName[$ - 1] != '/')
            archiveName ~= '/';

        archive_entry_clear(entry);
        archive_entry_set_pathname_utf8(entry, archiveName.toStringz);
        archive_entry_set_size(entry, 0);
        archive_entry_set_mode(entry, AE_IFDIR | permissions);

        auto r = archive_write_header(a, entry);
        enforceArchiveOk(a, r, "writing directory header");
        archive_write_finish_entry(a);

        return this;
    }

    /// Add from streaming source.
    /// size: byte count if known (-1 = unknown). Provide size for tar/cpio/7z.
    ref DarkArchiveWriter addStream(string archiveName,
                                     scope void delegate(scope void delegate(const(ubyte)[])) reader,
                                     long size = -1,
                                     uint permissions = octal!644) @trusted {
        auto a = handle;
        auto entry = _payload._entry;

        archive_entry_clear(entry);
        archive_entry_set_pathname_utf8(entry, archiveName.toStringz);
        archive_entry_set_mode(entry, AE_IFREG | permissions);

        if (size >= 0)
            archive_entry_set_size(entry, size);
        else
            archive_entry_unset_size(entry);

        auto r = archive_write_header(a, entry);
        enforceArchiveOk(a, r, "writing stream header");

        reader((const(ubyte)[] chunk) {
            if (chunk.length > 0) {
                auto written = archive_write_data(a, chunk.ptr, chunk.length);
                if (written < 0)
                    enforceArchiveOk(a, cast(int) written, "writing stream data");
            }
        });

        archive_write_finish_entry(a);

        return this;
    }

    /// Add symlink.
    ref DarkArchiveWriter addSymlink(string archiveName, string target,
                                      uint permissions = octal!777) @trusted {
        auto a = handle;
        auto entry = _payload._entry;

        archive_entry_clear(entry);
        archive_entry_set_pathname_utf8(entry, archiveName.toStringz);
        archive_entry_set_size(entry, 0);
        archive_entry_set_mode(entry, AE_IFLNK | permissions);
        archive_entry_set_symlink_utf8(entry, target.toStringz);

        auto r = archive_write_header(a, entry);
        enforceArchiveOk(a, r, "writing symlink header");
        archive_write_finish_entry(a);

        return this;
    }

    // -- Options --

    /// Set passphrase for encryption (zip).
    ref DarkArchiveWriter setPassphrase(string passphrase) @trusted {
        auto r = archive_write_set_passphrase(handle, passphrase.toStringz);
        enforceArchiveOk(handle, r, "setting passphrase");
        return this;
    }

    /// Set format-specific option.
    ref DarkArchiveWriter setOption(string module_, string option, string value) @trusted {
        auto r = archive_write_set_option(handle,
            module_ is null ? null : module_.toStringz,
            option.toStringz,
            value.toStringz);
        enforceArchiveOk(handle, r, "setting option");
        return this;
    }

    // -- Finalize --

    /// Finish writing. Called automatically when last ref drops.
    void finish() @trusted {
        _payload.finish();
    }

    /// For memory writer: returns written data after finish().
    const(ubyte)[] writtenData() @trusted {
        finish();
        if (_payload._memBuf is null)
            return null;
        return _payload._memBuf[0 .. _payload._memUsed];
    }

    // -- Private helpers --

    private static void setFormat(archive* a, DarkArchiveFormat fmt) @trusted {
        int r;
        final switch (fmt) {
            case DarkArchiveFormat.zip:           r = archive_write_set_format_zip(a); break;
            case DarkArchiveFormat.tar:           r = archive_write_set_format_pax_restricted(a); break;
            case DarkArchiveFormat.pax:           r = archive_write_set_format_pax(a); break;
            case DarkArchiveFormat.paxRestricted: r = archive_write_set_format_pax_restricted(a); break;
            case DarkArchiveFormat.gnutar:        r = archive_write_set_format_gnutar(a); break;
            case DarkArchiveFormat.ustar:         r = archive_write_set_format_ustar(a); break;
            case DarkArchiveFormat.v7tar:         r = archive_write_set_format_v7tar(a); break;
            case DarkArchiveFormat.sevenZip:      r = archive_write_set_format_7zip(a); break;
            case DarkArchiveFormat.cpio:          r = archive_write_set_format_cpio(a); break;
            case DarkArchiveFormat.cpioNewc:      r = archive_write_set_format_cpio_newc(a); break;
            case DarkArchiveFormat.cpioOdc:       r = archive_write_set_format_cpio_odc(a); break;
            case DarkArchiveFormat.cpioBin:       r = archive_write_set_format_cpio_bin(a); break;
            case DarkArchiveFormat.cpioPwb:       r = archive_write_set_format_cpio_pwb(a); break;
            case DarkArchiveFormat.iso9660:       r = archive_write_set_format_iso9660(a); break;
            case DarkArchiveFormat.ar:            r = archive_write_set_format_ar_svr4(a); break;
            case DarkArchiveFormat.arBsd:         r = archive_write_set_format_ar_bsd(a); break;
            case DarkArchiveFormat.arSvr4:        r = archive_write_set_format_ar_svr4(a); break;
            case DarkArchiveFormat.xar:           r = archive_write_set_format_xar(a); break;
            case DarkArchiveFormat.warc:          r = archive_write_set_format_warc(a); break;
            case DarkArchiveFormat.shar:          r = archive_write_set_format_shar(a); break;
            case DarkArchiveFormat.sharDump:      r = archive_write_set_format_shar_dump(a); break;
            case DarkArchiveFormat.mtree:         r = archive_write_set_format_mtree(a); break;
            case DarkArchiveFormat.mtreeClassic:  r = archive_write_set_format_mtree_classic(a); break;
            case DarkArchiveFormat.raw:           r = archive_write_set_format_raw(a); break;
        }
        enforceArchiveOk(a, r, "setting format");
    }

    private static void setFilter(archive* a, DarkArchiveFilter filter) @trusted {
        int r;
        final switch (filter) {
            case DarkArchiveFilter.none:      r = archive_write_add_filter_none(a); break;
            case DarkArchiveFilter.gzip:      r = archive_write_add_filter_gzip(a); break;
            case DarkArchiveFilter.bzip2:     r = archive_write_add_filter_bzip2(a); break;
            case DarkArchiveFilter.xz:        r = archive_write_add_filter_xz(a); break;
            case DarkArchiveFilter.lzma:      r = archive_write_add_filter_lzma(a); break;
            case DarkArchiveFilter.zstd:      r = archive_write_add_filter_zstd(a); break;
            case DarkArchiveFilter.lz4:       r = archive_write_add_filter_lz4(a); break;
            case DarkArchiveFilter.lzip:      r = archive_write_add_filter_lzip(a); break;
            case DarkArchiveFilter.lzop:      r = archive_write_add_filter_lzop(a); break;
            case DarkArchiveFilter.compress:  r = archive_write_add_filter_compress(a); break;
            case DarkArchiveFilter.grzip:     r = archive_write_add_filter_grzip(a); break;
            case DarkArchiveFilter.lrzip:     r = archive_write_add_filter_lrzip(a); break;
            case DarkArchiveFilter.uuencode:  r = archive_write_add_filter_uuencode(a); break;
            case DarkArchiveFilter.b64encode: r = archive_write_add_filter_b64encode(a); break;
        }
        enforceArchiveOk(a, r, "setting filter");
    }
}


// ===========================================================================
// Unit tests
// ===========================================================================

version(unittest) {
    import unit_threaded.assertions : shouldEqual, shouldNotEqual, shouldBeNull,
        shouldNotBeNull, shouldBeTrue, shouldBeFalse, shouldBeGreaterThan;

    private immutable testDataDir = "test-data";

    /// 1. Version query
    @("getLibArchiveVersion returns non-empty string")
    unittest {
        import darkarchive : getLibArchiveVersion;
        auto ver = getLibArchiveVersion();
        assert(ver !is null && ver.length > 0, "version string should not be empty");
    }

    /// 2. Read tar.gz
    @("read tar.gz -- iterate entries and verify content")
    unittest {
        auto reader = DarkArchiveReader(Path(testDataDir, "test.tar.gz"));
        string[] names;
        foreach (entry; reader.entries) {
            auto name = entry.pathname;
            names ~= name;
            if (name == "./file1.txt") {
                auto content = reader.readText();
                content.shouldEqual("Hello from file1\n");
            } else if (name == "./file2.txt") {
                auto content = reader.readText();
                content.shouldEqual("Hello from file2\n");
            } else if (name == "./subdir/nested.txt") {
                auto content = reader.readText();
                content.shouldEqual("Nested file content\n");
            } else {
                reader.skipData();
            }
        }
        assert(names.length > 0, "should have found entries");
    }

    /// 3. Read zip
    @("read zip -- iterate entries and verify content")
    unittest {
        auto reader = DarkArchiveReader(Path(testDataDir, "test-zip.zip"));
        string[] names;
        foreach (entry; reader.entries) {
            auto name = entry.pathname;
            names ~= name;
            if (name == "file1.txt") {
                auto content = reader.readText();
                content.shouldEqual("Hello from file1\n");
            } else if (name == "file2.txt") {
                auto content = reader.readText();
                content.shouldEqual("Hello from file2\n");
            } else if (name == "subdir/nested.txt") {
                auto content = reader.readText();
                content.shouldEqual("Nested file content\n");
            } else {
                reader.skipData();
            }
        }
        assert(names.length > 0, "should have found entries");
    }

    /// 4. Write zip and read back
    @("write zip -- round-trip with addBuffer")
    unittest {
        import std.file : remove, exists;

        auto outPath = Path(testDataDir, "test-write.zip");
        scope(exit) if (exists(outPath.toString)) remove(outPath.toString);

        // Write
        {
            auto writer = DarkArchiveWriter(outPath);
            writer
                .addBuffer("hello.txt", cast(const(ubyte)[]) "Hello World!")
                .addBuffer("data/nested.txt", cast(const(ubyte)[]) "Nested content")
                .addDirectory("emptydir");
        }

        // Read back
        auto reader = DarkArchiveReader(outPath);
        bool foundHello, foundNested, foundDir;
        foreach (entry; reader.entries) {
            auto name = entry.pathname;
            if (name == "hello.txt") {
                foundHello = true;
                reader.readText().shouldEqual("Hello World!");
            } else if (name == "data/nested.txt") {
                foundNested = true;
                reader.readText().shouldEqual("Nested content");
            } else if (name == "emptydir/") {
                foundDir = true;
                entry.isDir.shouldBeTrue;
                reader.skipData();
            } else {
                reader.skipData();
            }
        }
        foundHello.shouldBeTrue;
        foundNested.shouldBeTrue;
        foundDir.shouldBeTrue;
    }

    /// 5. Write tar.gz and read back
    @("write tar.gz -- round-trip with explicit format+filter")
    unittest {
        import std.file : remove, exists;

        auto outPath = Path(testDataDir, "test-write.tar.gz");
        scope(exit) if (exists(outPath.toString)) remove(outPath.toString);

        {
            auto writer = DarkArchiveWriter(outPath, DarkArchiveFormat.tar, DarkArchiveFilter.gzip);
            writer
                .addBuffer("file-a.txt", cast(const(ubyte)[]) "Content A")
                .addBuffer("file-b.txt", cast(const(ubyte)[]) "Content B");
        }

        auto reader = DarkArchiveReader(outPath);
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

    /// 6. Write tar.zst and read back
    @("write tar.zst -- round-trip")
    unittest {
        import std.file : remove, exists;

        auto outPath = Path(testDataDir, "test-write.tar.zst");
        scope(exit) if (exists(outPath.toString)) remove(outPath.toString);

        {
            auto writer = DarkArchiveWriter(outPath, DarkArchiveFormat.tar, DarkArchiveFilter.zstd);
            writer.addBuffer("zstd-test.txt", cast(const(ubyte)[]) "Zstandard content");
        }

        auto reader = DarkArchiveReader(outPath);
        foreach (entry; reader.entries) {
            if (entry.pathname == "zstd-test.txt")
                reader.readText().shouldEqual("Zstandard content");
            else
                reader.skipData();
        }
    }

    /// 7. Streaming write with addStream
    @("addStream -- streaming write round-trip")
    unittest {
        import std.file : remove, exists;

        auto outPath = Path(testDataDir, "test-stream.zip");
        scope(exit) if (exists(outPath.toString)) remove(outPath.toString);

        auto testData = cast(const(ubyte)[]) "Streamed content chunk1chunk2";

        {
            auto writer = DarkArchiveWriter(outPath);
            writer.addStream("streamed.txt", (scope sink) {
                sink(cast(const(ubyte)[]) "Streamed content ");
                sink(cast(const(ubyte)[]) "chunk1");
                sink(cast(const(ubyte)[]) "chunk2");
            });
        }

        auto reader = DarkArchiveReader(outPath);
        foreach (entry; reader.entries) {
            if (entry.pathname == "streamed.txt") {
                auto content = reader.readText();
                content.shouldEqual("Streamed content chunk1chunk2");
            } else {
                reader.skipData();
            }
        }
    }

    /// 8. Streaming read -- readData and readDataNoCopy
    @("readData and readDataNoCopy -- chunk-based reading")
    unittest {
        import std.array : appender;

        auto reader = DarkArchiveReader(Path(testDataDir, "test-zip.zip"));
        foreach (entry; reader.entries) {
            if (entry.pathname == "file1.txt") {
                // Test readDataNoCopy
                auto buf = appender!(ubyte[])();
                foreach (chunk; reader.readDataNoCopy())
                    buf ~= chunk;
                (cast(string) buf[]).shouldEqual("Hello from file1\n");
                break;
            } else {
                reader.skipData();
            }
        }
    }

    /// 9. Extract to directory
    @("extractTo -- extract archive to directory")
    unittest {
        import std.file : remove, exists, readText, rmdirRecurse, mkdirRecurse;

        auto extractDir = Path(testDataDir, "extract-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(Path(testDataDir, "test-zip.zip"));
        reader.extractTo(extractDir);

        assert(exists((extractDir ~ "file1.txt").toString));
        readText((extractDir ~ "file1.txt").toString).shouldEqual("Hello from file1\n");
        assert(exists((extractDir ~ "subdir/nested.txt").toString));
        readText((extractDir ~ "subdir/nested.txt").toString).shouldEqual("Nested file content\n");
    }

    /// 10. Method chaining
    @("method chaining -- fluent API works")
    unittest {
        import std.file : remove, exists;

        auto outPath = Path(testDataDir, "test-chain.zip");
        scope(exit) if (exists(outPath.toString)) remove(outPath.toString);

        {
            auto writer = DarkArchiveWriter(outPath);
            writer
                .addBuffer("a.txt", cast(const(ubyte)[]) "A")
                .addBuffer("b.txt", cast(const(ubyte)[]) "B")
                .addBuffer("c.txt", cast(const(ubyte)[]) "C");
        }

        auto reader = DarkArchiveReader(outPath);
        int count;
        foreach (entry; reader.entries) {
            count++;
            reader.skipData();
        }
        count.shouldEqual(3);
    }

    /// 11. Large entry -- data > 8192 bytes streams correctly
    @("large entry -- verify multi-chunk streaming")
    unittest {
        import std.file : remove, exists;
        import std.array : appender;

        auto outPath = Path(testDataDir, "test-large.zip");
        scope(exit) if (exists(outPath.toString)) remove(outPath.toString);

        // Create 32KB of data
        auto largeData = new ubyte[](32768);
        foreach (i, ref b; largeData)
            b = cast(ubyte)(i % 256);

        {
            auto writer = DarkArchiveWriter(outPath);
            writer.addBuffer("large.bin", largeData);
        }

        auto reader = DarkArchiveReader(outPath);
        foreach (entry; reader.entries) {
            if (entry.pathname == "large.bin") {
                auto content = reader.readAll();
                content.length.shouldEqual(32768);
                content.shouldEqual(largeData);
            } else {
                reader.skipData();
            }
        }
    }

    /// 12. Error handling -- non-existent file
    @("error handling -- non-existent file throws")
    unittest {
        bool caught;
        try {
            auto reader = DarkArchiveReader(Path("nonexistent-file.tar.gz"));
        } catch (DarkArchiveException e) {
            caught = true;
        }
        caught.shouldBeTrue;
    }

    /// 13. Cross-format -- write as zip, read; write as tar.gz, read
    @("cross-format -- same data readable from different formats")
    unittest {
        import std.file : remove, exists;

        auto zipPath = Path(testDataDir, "test-cross.zip");
        auto tarPath = Path(testDataDir, "test-cross.tar.gz");
        scope(exit) {
            if (exists(zipPath.toString)) remove(zipPath.toString);
            if (exists(tarPath.toString)) remove(tarPath.toString);
        }

        auto testContent = cast(const(ubyte)[]) "Cross-format test content";

        // Write as zip
        { DarkArchiveWriter(zipPath).addBuffer("cross.txt", testContent); }
        // Write as tar.gz
        { DarkArchiveWriter(tarPath, DarkArchiveFormat.tar, DarkArchiveFilter.gzip)
              .addBuffer("cross.txt", testContent); }

        // Read from zip
        {
            auto r = DarkArchiveReader(zipPath);
            foreach (e; r.entries) {
                if (e.pathname == "cross.txt")
                    r.readText().shouldEqual("Cross-format test content");
                else
                    r.skipData();
            }
        }

        // Read from tar.gz
        {
            auto r2 = DarkArchiveReader(tarPath);
            foreach (entry; r2.entries) {
                if (entry.pathname == "cross.txt")
                    r2.readText().shouldEqual("Cross-format test content");
                else
                    r2.skipData();
            }
        }
    }

    /// 14. Entry properties
    @("entry properties -- verify file type detection")
    unittest {
        import std.file : remove, exists;

        auto outPath = Path(testDataDir, "test-props.zip");
        scope(exit) if (exists(outPath.toString)) remove(outPath.toString);

        {
            auto writer = DarkArchiveWriter(outPath);
            writer
                .addBuffer("file.txt", cast(const(ubyte)[]) "content")
                .addDirectory("mydir");
        }

        auto reader = DarkArchiveReader(outPath);
        foreach (entry; reader.entries) {
            if (entry.pathname == "file.txt") {
                entry.isFile.shouldBeTrue;
                entry.isDir.shouldBeFalse;
                entry.size.shouldEqual(7);
            } else if (entry.pathname == "mydir/") {
                entry.isDir.shouldBeTrue;
                entry.isFile.shouldBeFalse;
            }
            reader.skipData();
        }
    }

    /// 15. Format metadata
    @("format metadata -- formatName and filterName")
    unittest {
        auto reader = DarkArchiveReader(Path(testDataDir, "test.tar.gz"));
        // Need to read at least one header for format detection
        foreach (entry; reader.entries) {
            reader.skipData();
            break;
        }
        auto fmtName = reader.formatName();
        assert(fmtName !is null && fmtName.length > 0);
    }

    // -----------------------------------------------------------------------
    // External archive / edge-case tests
    // -----------------------------------------------------------------------

    /// 16. Empty archive -- iteration produces zero entries
    @("empty archive -- zero entries without error")
    unittest {
        auto reader = DarkArchiveReader(Path(testDataDir, "test-empty.tar.gz"));
        int count;
        foreach (entry; reader.entries) {
            count++;
            reader.skipData();
        }
        count.shouldEqual(0);
    }

    /// 17. Symlink archive -- read symlink entry from external tar
    @("symlink archive -- isSymlink and symlinkTarget")
    unittest {
        auto reader = DarkArchiveReader(Path(testDataDir, "test-symlink.tar"));
        bool foundLink, foundTarget;
        foreach (entry; reader.entries) {
            auto name = entry.pathname;
            if (name == "./link.txt") {
                foundLink = true;
                entry.isSymlink.shouldBeTrue;
                entry.isFile.shouldBeFalse;
                entry.symlinkTarget.shouldEqual("target.txt");
            } else if (name == "./target.txt") {
                foundTarget = true;
                entry.isFile.shouldBeTrue;
                reader.readText().shouldEqual("target content\n");
            }
            if (!entry.isFile)
                reader.skipData();
        }
        foundLink.shouldBeTrue;
        foundTarget.shouldBeTrue;
    }

    /// 18. Unicode filenames
    /// NOTE: libarchive requires LC_CTYPE to support UTF-8 for non-ASCII
    /// pathnames. D's runtime starts with LC_ALL="C" which cannot represent
    /// multibyte characters. Users must call setlocale(LC_CTYPE, "C.UTF-8")
    /// or setlocale(LC_CTYPE, "") in their main() for non-ASCII pathname
    /// support. This test sets locale explicitly to demonstrate.
    @("unicode filenames -- UTF-8 pathnames from external zip")
    unittest {
        import core.stdc.locale : setlocale, LC_CTYPE;
        import std.string : fromStringz;

        // Save and set UTF-8 locale for this test
        auto saved = setlocale(LC_CTYPE, null);
        import std.stdio;
        writefln("XXX: %s", saved.fromStringz);
        //scope(exit) setlocale(LC_CTYPE, saved);
        //setlocale(LC_CTYPE, "C.UTF-8");

        auto reader = DarkArchiveReader(Path(testDataDir, "test-unicode.zip"));
        string[] names;
        foreach (entry; reader.entries) {
            names ~= entry.pathname;
            reader.skipData();
        }
        import std.algorithm : canFind;
        import std.string : join;
        assert(names.canFind("café.txt"), "should find café.txt, got: " ~ names.join(", "));
        assert(names.canFind("日本語.txt"), "should find 日本語.txt, got: " ~ names.join(", "));
    }

    /// 19. Plain .gz (format_raw) -- single compressed file, not a tar
    @("plain gzip -- format_raw reads single compressed stream")
    unittest {
        auto reader = DarkArchiveReader(Path(testDataDir, "test-single-file.gz"));
        int count;
        foreach (entry; reader.entries) {
            count++;
            auto content = reader.readText();
            assert(content.length > 0, "should have content");
            assert(content == "This is a plain gzip compressed file, not a tar archive.\n",
                "unexpected content: " ~ content);
        }
        count.shouldEqual(1);
    }

    /// 20. tar.zst -- read archive created by system zstd tool
    @("tar.zst -- cross-tool interop with system zstd")
    unittest {
        auto reader = DarkArchiveReader(Path(testDataDir, "test.tar.zst"));
        string[] names;
        foreach (entry; reader.entries) {
            auto name = entry.pathname;
            names ~= name;
            if (name == "./file1.txt") {
                reader.readText().shouldEqual("Hello from file1\n");
            } else if (name == "./file2.txt") {
                reader.readText().shouldEqual("Hello from file2\n");
            } else if (name == "./subdir/nested.txt") {
                reader.readText().shouldEqual("Nested file content\n");
            } else {
                reader.skipData();
            }
        }
        assert(names.length > 0, "should have found entries in tar.zst");
    }

    /// 21. Zero-byte files
    @("zero-byte files -- size 0 but isFile true, readAll returns empty")
    unittest {
        auto reader = DarkArchiveReader(Path(testDataDir, "test-empty-files.tar"));
        bool foundGitkeep, foundEmpty, foundNotempty;
        foreach (entry; reader.entries) {
            auto name = entry.pathname;
            if (name == "./.gitkeep") {
                foundGitkeep = true;
                entry.isFile.shouldBeTrue;
                entry.size.shouldEqual(0);
                reader.readAll().length.shouldEqual(0);
            } else if (name == "./empty.txt") {
                foundEmpty = true;
                entry.isFile.shouldBeTrue;
                entry.size.shouldEqual(0);
                reader.readAll().length.shouldEqual(0);
            } else if (name == "./notempty.txt") {
                foundNotempty = true;
                entry.isFile.shouldBeTrue;
                entry.size.shouldBeGreaterThan(0);
                reader.readText().shouldEqual("notempty\n");
            } else {
                reader.skipData();
            }
        }
        foundGitkeep.shouldBeTrue;
        foundEmpty.shouldBeTrue;
        foundNotempty.shouldBeTrue;
    }

    /// 22. Many entries (150 files)
    @("many entries -- 150 files, no off-by-one")
    unittest {
        auto reader = DarkArchiveReader(Path(testDataDir, "test-many-entries.zip"));
        int count;
        foreach (entry; reader.entries) {
            count++;
            if (entry.isFile) {
                auto content = reader.readText();
                assert(content.length > 0, "each file should have content");
            } else {
                reader.skipData();
            }
        }
        count.shouldEqual(150);
    }

    /// 23. Deep path
    @("deep path -- deeply nested directory structure")
    unittest {
        auto reader = DarkArchiveReader(Path(testDataDir, "test-deep-path.zip"));
        bool foundDeep;
        foreach (entry; reader.entries) {
            if (entry.pathname == "a/b/c/d/e/f/g/deep.txt") {
                foundDeep = true;
                reader.readText().shouldEqual("deep content\n");
            } else {
                reader.skipData();
            }
        }
        foundDeep.shouldBeTrue;
    }

    /// 24. Large entry from external tool (128KB random data)
    @("large entry -- 128KB file, multi-chunk read from external tar.gz")
    unittest {
        auto reader = DarkArchiveReader(Path(testDataDir, "test-large-entry.tar.gz"));
        foreach (entry; reader.entries) {
            if (entry.pathname == "large-128k.bin") {
                entry.isFile.shouldBeTrue;
                auto data = reader.readAll();
                data.length.shouldEqual(128 * 1024);

                // Verify readDataNoCopy produces same result
                auto reader2 = DarkArchiveReader(Path(testDataDir, "test-large-entry.tar.gz"));
                foreach (entry2; reader2.entries) {
                    if (entry2.pathname == "large-128k.bin") {
                        import std.array : appender;
                        auto buf = appender!(ubyte[])();
                        foreach (chunk; reader2.readDataNoCopy())
                            buf ~= chunk;
                        buf[].length.shouldEqual(128 * 1024);
                        buf[].shouldEqual(data);
                    } else {
                        reader2.skipData();
                    }
                }
            } else {
                reader.skipData();
            }
        }
    }
}
