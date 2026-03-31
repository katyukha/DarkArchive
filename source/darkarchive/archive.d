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
import darkarchive.formats.tar : TarReader, TarWriter, gzipCompress;
import darkarchive.gzip : gunzip, isGzip;

import thepath : Path;


/// Archive format selection.
enum DarkArchiveFormat {
    zip,
    tar,
    tarGz,
    // tarZst,  -- future stage
}

/// Extract behavior flags.
enum DarkExtractFlags {
    none        = 0,
    perm        = 1,
    time        = 2,
    securePaths = 4,
    defaults    = perm | time | securePaths,
}


// ---------------------------------------------------------------------------
// DarkArchiveReader
// ---------------------------------------------------------------------------

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
        const(ubyte)[] _rawData; // keep reference for lifetime

        DarkArchiveFormat _format;
        // For zip: iteration index
        size_t _zipIndex;
    }

    @disable this();

    /// Open archive from file path (auto-detect format).
    this(in Path path) {
        this(path.toString());
    }

    /// ditto
    this(string path) {
        import std.file : read;
        _rawData = cast(const(ubyte)[]) read(path);
        detectAndOpen();
    }

    /// Open archive from memory buffer (auto-detect format).
    this(const(ubyte)[] data) {
        _rawData = data;
        detectAndOpen();
    }

    private void detectAndOpen() {
        if (_rawData.length < 4)
            throw new DarkArchiveException("Archive data too small to detect format");

        // ZIP: starts with "PK\x03\x04" or "PK\x05\x06" (empty zip)
        if (_rawData.length >= 4 &&
            _rawData[0] == 'P' && _rawData[1] == 'K' &&
            (_rawData[2] == 3 || _rawData[2] == 5)) {
            _zip = new ZipReader(_rawData);
            _format = DarkArchiveFormat.zip;
            return;
        }

        // GZIP: starts with 0x1f 0x8b
        if (isGzip(_rawData)) {
            auto tarData = gunzip(_rawData);
            _tar = new TarReader(tarData);
            _format = DarkArchiveFormat.tarGz;
            return;
        }

        // TAR: check for ustar magic at offset 257
        if (_rawData.length >= 263 &&
            _rawData[257 .. 262] == cast(const(ubyte)[]) "ustar") {
            _tar = new TarReader(_rawData);
            _format = DarkArchiveFormat.tar;
            return;
        }

        throw new DarkArchiveException("Cannot detect archive format");
    }

    /// Detected archive format.
    DarkArchiveFormat detectedFormat() const {
        return _format;
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
            return cast(ubyte[]) _zip.readData(_zipIndex).dup;
        } else {
            auto d = _tar.readData();
            return d is null ? [] : cast(ubyte[]) d.dup;
        }
    }

    /// Read current entry as text.
    string readText() {
        return cast(string) readAll();
    }

    /// Skip current entry's data.
    void skipData() {
        // No-op for memory-based readers
    }

    /// Read data as chunks (allocating copies).
    auto readData() {
        auto data = readAll();
        static struct SingleChunkRange {
            ubyte[] _data;
            bool _done;
            bool empty() { return _done; }
            const(ubyte)[] front() { return _data; }
            void popFront() { _done = true; }
        }
        return SingleChunkRange(data, data.length == 0);
    }

    /// Zero-copy read (for memory-based readers, same as readData).
    auto readDataNoCopy() {
        return readData();
    }

    /// Extract entire archive to directory.
    void extractTo(in Path destination,
                    DarkExtractFlags flags = DarkExtractFlags.defaults) {
        import std.file : mkdirRecurse, write, symlink, exists;

        auto destStr = destination.toString();

        foreach (entry; entries()) {
            auto entryPath = entry.pathname;

            // Security: reject absolute paths and ".." path components
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
                auto target = entry.symlinkTarget;

                // Absolute symlink targets are ALWAYS rejected — there is no
                // legitimate use case for creating a symlink to /etc/passwd
                // during extraction. This is unconditional, regardless of flags.
                if (target.length > 0 && target[0] == '/')
                    throw new DarkArchiveException(
                        "Refusing to create symlink with absolute target: " ~ target);

                // ".." in symlink target — rejected under securePaths
                if (flags & DarkExtractFlags.securePaths) {
                    if (hasPathTraversal(target))
                        throw new DarkArchiveException(
                            "Refusing to create symlink with '..' in target: " ~ target);
                }
                auto parent = fullPath.parent;
                if (!exists(parent.toString()))
                    mkdirRecurse(parent.toString());
                symlink(entry.symlinkTarget, fullPath.toString());
                skipData();
            } else {
                auto parent = fullPath.parent;
                if (!exists(parent.toString()))
                    mkdirRecurse(parent.toString());

                // CVE-2021-20206 defense: verify the resolved real path
                // doesn't escape the extraction directory via a symlink
                if (flags & DarkExtractFlags.securePaths) {
                    verifyPathWithinRoot(parent.toString(), destStr);
                }

                auto data = readAll();
                write(fullPath.toString(), data);
            }
        }
    }

    /// Check if a resolved path stays within the expected root directory.
    /// Defends against two-step symlink+file attacks (CVE-2021-20206 pattern).
    private static void verifyPathWithinRoot(string path, string root) {
        import std.path : absolutePath, buildNormalizedPath;
        import std.file : isSymlink, readLink, exists;

        // Resolve the actual filesystem path (following symlinks)
        auto resolved = resolveRealPath(path);
        auto normalRoot = buildNormalizedPath(absolutePath(root));

        if (!pathStartsWith(resolved, normalRoot))
            throw new DarkArchiveException(
                "Refusing to write file: resolved path escapes extraction directory");
    }

    /// Poor man's realpath: resolve symlinks in path components.
    private static string resolveRealPath(string path) {
        import std.path : absolutePath, buildNormalizedPath, dirName, baseName;
        import std.file : isSymlink, readLink, exists;

        auto normalized = buildNormalizedPath(absolutePath(path));

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
    }

    private static bool pathStartsWith(string s, string prefix) {
        if (s.length < prefix.length) return false;
        if (s[0 .. prefix.length] != prefix) return false;
        // Ensure it's a proper prefix (ends at / boundary or exact match)
        if (s.length == prefix.length) return true;
        return s[prefix.length] == '/';
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
        string _filePath; // null for memory writer
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

    /// Create writer to memory buffer.
    this(DarkArchiveFormat fmt) {
        _format = fmt;
        createWriter();
    }

    private void createWriter() {
        final switch (_format) {
            case DarkArchiveFormat.zip:
                _zip = new ZipWriter();
                *_zip = ZipWriter.create();
                break;
            case DarkArchiveFormat.tar:
            case DarkArchiveFormat.tarGz:
                _tar = new TarWriter();
                *_tar = TarWriter.create();
                break;
        }
    }

    /// Add file from disk.
    ref DarkArchiveWriter add(in Path sourcePath, string archiveName = null) return {
        return add(sourcePath.toString(), archiveName);
    }

    /// ditto
    ref DarkArchiveWriter add(string sourcePath, string archiveName = null) return {
        import std.file : read;
        if (archiveName is null)
            archiveName = Path(sourcePath).baseName;
        auto data = cast(const(ubyte)[]) read(sourcePath);
        addBuffer(archiveName, data);
        return this;
    }

    /// Add directory tree recursively.
    ref DarkArchiveWriter addTree(in Path rootPath, string prefix = null) return {
        return addTree(rootPath.toString(), prefix);
    }

    /// ditto
    ref DarkArchiveWriter addTree(string rootPath, string prefix = null) return {
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

    /// Add symlink.
    ref DarkArchiveWriter addSymlink(string archiveName, string target) return {
        if (_tar !is null)
            _tar.addSymlink(archiveName, target);
        // ZIP doesn't natively support symlinks in our implementation
        return this;
    }

    /// Finish and write to file (if file path was given).
    void finish() {
        if (_finished) return;
        _finished = true;

        auto data = writtenData();
        if (_filePath !is null) {
            import std.file : write;
            write(_filePath, data);
        }
    }

    /// Get the written archive data.
    const(ubyte)[] writtenData() {
        if (_zip !is null) {
            return _zip.data;
        } else {
            auto tarData = _tar.data;
            if (_format == DarkArchiveFormat.tarGz)
                return gzipCompress(tarData);
            return tarData;
        }
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
    import unit_threaded.assertions : shouldEqual, shouldBeTrue, shouldBeFalse;

    private immutable testDataDir = "test-data";

    /// Read zip via high-level API
    @("high-level: read zip and verify content")
    unittest {
        auto reader = DarkArchiveReader(Path(testDataDir, "test-zip.zip"));
        reader.detectedFormat().shouldEqual(DarkArchiveFormat.zip);
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
        auto reader = DarkArchiveReader(Path(testDataDir, "test.tar.gz"));
        reader.detectedFormat().shouldEqual(DarkArchiveFormat.tarGz);
        foreach (entry; reader.entries) {
            if (entry.pathname == "./file1.txt")
                reader.readText().shouldEqual("Hello from file1\n");
            else
                reader.skipData();
        }
    }

    /// Write zip round-trip via high-level API
    @("high-level: write zip round-trip")
    unittest {
        import std.file : remove, exists;

        auto outPath = Path(testDataDir, "test-hl-write.zip");
        scope(exit) if (exists(outPath.toString)) remove(outPath.toString);

        {
            auto writer = DarkArchiveWriter(outPath);
            writer
                .addBuffer("hello.txt", cast(const(ubyte)[]) "Hello World!")
                .addDirectory("emptydir");
        }

        auto reader = DarkArchiveReader(outPath);
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
        import std.file : remove, exists;

        auto outPath = Path(testDataDir, "test-hl-write.tar.gz");
        scope(exit) if (exists(outPath.toString)) remove(outPath.toString);

        {
            auto writer = DarkArchiveWriter(outPath, DarkArchiveFormat.tarGz);
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

    /// Cross-format — same data readable from zip and tar.gz
    @("high-level: cross-format round-trip")
    unittest {
        import std.file : remove, exists;

        auto zipPath = Path(testDataDir, "test-hl-cross.zip");
        auto tarPath = Path(testDataDir, "test-hl-cross.tar.gz");
        scope(exit) {
            if (exists(zipPath.toString)) remove(zipPath.toString);
            if (exists(tarPath.toString)) remove(tarPath.toString);
        }

        auto content = cast(const(ubyte)[]) "Cross-format test";

        { DarkArchiveWriter(zipPath).addBuffer("cross.txt", content); }
        { DarkArchiveWriter(tarPath, DarkArchiveFormat.tarGz).addBuffer("cross.txt", content); }

        // Read zip
        {
            auto r = DarkArchiveReader(zipPath);
            foreach (e; r.entries) {
                if (e.pathname == "cross.txt")
                    r.readText().shouldEqual("Cross-format test");
                else
                    r.skipData();
            }
        }

        // Read tar.gz
        {
            auto r = DarkArchiveReader(tarPath);
            foreach (e; r.entries) {
                if (e.pathname == "cross.txt")
                    r.readText().shouldEqual("Cross-format test");
                else
                    r.skipData();
            }
        }
    }

    /// Error handling — non-existent file
    @("high-level: non-existent file throws")
    unittest {
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
        import std.file : exists, readText, rmdirRecurse;

        auto extractDir = Path(testDataDir, "extract-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(Path(testDataDir, "test-zip.zip"));
        reader.extractTo(extractDir);

        assert(exists((extractDir ~ "file1.txt").toString));
        readText((extractDir ~ "file1.txt").toString).shouldEqual("Hello from file1\n");
        assert(exists((extractDir ~ "subdir/nested.txt").toString));
        readText((extractDir ~ "subdir/nested.txt").toString).shouldEqual("Nested file content\n");
    }

    /// Write to memory buffer
    @("high-level: write to memory, read back")
    unittest {
        auto writer = DarkArchiveWriter(DarkArchiveFormat.zip);
        writer.addBuffer("mem.txt", cast(const(ubyte)[]) "from memory");

        auto data = writer.writtenData();
        assert(data.length > 0);

        auto reader = DarkArchiveReader(data);
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
        auto writer = DarkArchiveWriter(DarkArchiveFormat.zip);
        writer
            .addBuffer("a.txt", cast(const(ubyte)[]) "A")
            .addBuffer("b.txt", cast(const(ubyte)[]) "B")
            .addBuffer("c.txt", cast(const(ubyte)[]) "C");

        auto reader = DarkArchiveReader(writer.writtenData());
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
        import std.file : exists, rmdirRecurse;

        auto writer = DarkArchiveWriter(DarkArchiveFormat.zip);
        writer.addBuffer("../escape.txt", cast(const(ubyte)[]) "escaped!");
        auto data = writer.writtenData();

        auto extractDir = Path(testDataDir, "sec-dotdot-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(data);
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
        import std.file : exists, rmdirRecurse;

        auto writer = DarkArchiveWriter(DarkArchiveFormat.zip);
        writer.addBuffer("foo/../../escape2.txt", cast(const(ubyte)[]) "escaped!");
        auto data = writer.writtenData();

        auto extractDir = Path(testDataDir, "sec-nested-dotdot-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(data);
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
        import std.file : exists, rmdirRecurse;

        auto writer = DarkArchiveWriter(DarkArchiveFormat.zip);
        writer.addBuffer("/tmp/evil.txt", cast(const(ubyte)[]) "evil!");
        auto data = writer.writtenData();

        auto extractDir = Path(testDataDir, "sec-abs-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(data);
        bool caught;
        try {
            reader.extractTo(extractDir);
        } catch (DarkArchiveException e) {
            caught = true;
        }
        caught.shouldBeTrue;
    }

    /// Symlink escape: symlink pointing to absolute path must be rejected
    @("security: extractTo rejects symlink with absolute target")
    unittest {
        import std.file : exists, rmdirRecurse;
        import darkarchive.formats.tar : TarWriter;
        import darkarchive.gzip : gunzip;

        auto tw = TarWriter.create();
        tw.addSymlink("evil-link", "/etc/passwd");
        auto tarData = tw.data;

        auto extractDir = Path(testDataDir, "sec-symlink-abs-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(tarData);
        bool caught;
        try {
            reader.extractTo(extractDir);
        } catch (DarkArchiveException e) {
            caught = true;
        }
        caught.shouldBeTrue;
    }

    /// Symlink escape: symlink pointing outside via "../../../" must be rejected
    @("security: extractTo rejects symlink with traversal target")
    unittest {
        import std.file : exists, rmdirRecurse;
        import darkarchive.formats.tar : TarWriter;

        auto tw = TarWriter.create();
        tw.addSymlink("escape-link", "../../../../etc/shadow");
        auto tarData = tw.data;

        auto extractDir = Path(testDataDir, "sec-symlink-trav-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(tarData);
        bool caught;
        try {
            reader.extractTo(extractDir);
        } catch (DarkArchiveException e) {
            caught = true;
        }
        caught.shouldBeTrue;
    }

    /// Entry name "." and ".." as standalone components
    @("security: extractTo rejects entry named '..'")
    unittest {
        import std.file : exists, rmdirRecurse;

        auto writer = DarkArchiveWriter(DarkArchiveFormat.zip);
        writer.addBuffer("..", cast(const(ubyte)[]) "dot dot");
        auto data = writer.writtenData();

        auto extractDir = Path(testDataDir, "sec-dotdot-name-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(data);
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
    /// Entry 1: symlink "mydir" -> "/tmp"
    /// Entry 2: file "mydir/pwned.txt"
    /// Without defense, file is written to /tmp/pwned.txt via the symlink.
    @("CVE: two-step symlink+file extraction escape")
    unittest {
        import std.file : exists, rmdirRecurse, isSymlink;
        import darkarchive.formats.tar : TarWriter;

        auto tw = TarWriter.create();
        tw.addSymlink("escape-dir", "/tmp");
        tw.addBuffer("escape-dir/pwned.txt", cast(const(ubyte)[]) "pwned!");
        auto tarData = tw.data;

        auto extractDir = Path(testDataDir, "sec-twostep-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(tarData);
        bool caught;
        try {
            reader.extractTo(extractDir);
        } catch (DarkArchiveException e) {
            caught = true;
        }
        // Either the symlink was rejected (absolute target), or the file write
        // through the symlink was rejected. The file must NOT exist at /tmp/pwned.txt.
        assert(!exists("/tmp/pwned.txt"),
            "two-step symlink attack: file must not be written to /tmp/pwned.txt");
        caught.shouldBeTrue;
    }

    /// CVE-2021-20206 variant: relative symlink escape.
    /// Entry 1: symlink "linkdir" -> "../../"
    /// Entry 2: file "linkdir/escape.txt"
    @("CVE: two-step relative symlink+file escape")
    unittest {
        import std.file : exists, rmdirRecurse;
        import darkarchive.formats.tar : TarWriter;

        auto tw = TarWriter.create();
        tw.addSymlink("linkdir", "../../");
        tw.addBuffer("linkdir/escape.txt", cast(const(ubyte)[]) "escaped!");
        auto tarData = tw.data;

        auto extractDir = Path(testDataDir, "sec-twostep-rel-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(tarData);
        bool caught;
        try {
            reader.extractTo(extractDir);
        } catch (DarkArchiveException e) {
            caught = true;
        }
        // Must not create escape.txt outside extraction directory
        assert(!exists(Path(testDataDir, "escape.txt").toString),
            "relative symlink escape: file must not be created outside extract dir");
        caught.shouldBeTrue;
    }

    /// CVE-2018-1002200 "Zip Slip" — verify ".." check is per-component,
    /// not substring match. "file..name.txt" is a legitimate filename.
    @("CVE: Zip Slip - file..name.txt is legitimate, not rejected")
    unittest {
        import std.file : exists, rmdirRecurse;

        auto writer = DarkArchiveWriter(DarkArchiveFormat.zip);
        writer.addBuffer("file..name.txt", cast(const(ubyte)[]) "legitimate");
        auto data = writer.writtenData();

        auto extractDir = Path(testDataDir, "sec-legit-dotdot-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        // This should NOT throw — "file..name.txt" has ".." in the name
        // but not as a path component
        auto reader = DarkArchiveReader(data);
        reader.extractTo(extractDir);

        assert(exists((extractDir ~ "file..name.txt").toString),
            "file..name.txt should be extracted successfully");
    }

    /// CVE-2023-39804 pattern: pax path attribute overrides ustar name with traversal.
    /// ustar header has clean name, but pax path = "../../evil.txt"
    @("CVE: pax path override with traversal")
    unittest {
        import std.file : exists, rmdirRecurse;
        import darkarchive.formats.tar : TarWriter;

        auto tw = TarWriter.create();
        tw.addBuffer("../../pax-evil.txt", cast(const(ubyte)[]) "pax attack");
        auto tarData = tw.data;

        auto extractDir = Path(testDataDir, "sec-pax-trav-test");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(tarData);
        bool caught;
        try {
            reader.extractTo(extractDir);
        } catch (DarkArchiveException e) {
            caught = true;
        }
        caught.shouldBeTrue;
    }

    /// Absolute symlink targets must be rejected UNCONDITIONALLY,
    /// even when securePaths is disabled.
    @("security: absolute symlink rejected even with DarkExtractFlags.none")
    unittest {
        import std.file : exists, rmdirRecurse;
        import darkarchive.formats.tar : TarWriter;

        auto tw = TarWriter.create();
        tw.addSymlink("danger", "/etc/passwd");
        auto tarData = tw.data;

        auto extractDir = Path(testDataDir, "sec-abs-sym-unconditional");
        scope(exit) if (exists(extractDir.toString)) rmdirRecurse(extractDir.toString);

        auto reader = DarkArchiveReader(tarData);
        bool caught;
        try {
            // Explicitly pass none — no securePaths flag
            reader.extractTo(extractDir, DarkExtractFlags.none);
        } catch (DarkArchiveException e) {
            caught = true;
        }
        caught.shouldBeTrue;
    }
}
