module darkarchive.entry;

import std.string : fromStringz;
import std.datetime.systime : SysTime;
import std.datetime.timezone : UTC;
import core.stdc.config : c_long;

import darkarchive.lib;

/// High-level wrapper around archive_entry*.
///
/// Entries can be either "borrowed" (pointer owned by the reader, valid only
/// during current header iteration) or "owned" (allocated by us, freed on
/// destruction). Non-copyable to prevent double-free.
struct DarkArchiveEntry {
    private archive_entry* _entry;
    private bool _owned;

    @disable this(this);

    /// Wrap an entry we don't own (from archive_read_next_header).
    /// The pointer is only valid while the parent reader is alive and
    /// on the current header.
    static DarkArchiveEntry borrow(archive_entry* e) @trusted {
        DarkArchiveEntry result;
        result._entry = e;
        result._owned = false;
        return result;
    }

    /// Create a new owned entry.
    static DarkArchiveEntry create() @trusted {
        DarkArchiveEntry result;
        result._entry = archive_entry_new();
        result._owned = true;
        return result;
    }

    @trusted ~this() {
        if (_owned && _entry !is null) {
            archive_entry_free(_entry);
            _entry = null;
        }
    }

    // -- Properties: pathname --

    string pathname() @trusted {
        // Prefer UTF-8 variant for proper unicode support
        auto p = archive_entry_pathname_utf8(_entry);
        if (p is null)
            p = archive_entry_pathname(_entry);
        return p is null ? null : p.fromStringz.idup;
    }

    void pathname(string p) @trusted {
        import std.string : toStringz;
        archive_entry_set_pathname_utf8(_entry, p.toStringz);
    }

    // -- Properties: size --

    long size() @trusted {
        return archive_entry_size(_entry);
    }

    void size(long s) @trusted {
        archive_entry_set_size(_entry, s);
    }

    bool sizeIsSet() @trusted {
        return archive_entry_size_is_set(_entry) != 0;
    }

    // -- Properties: file type --

    bool isFile() @trusted {
        return (archive_entry_filetype(_entry) & AE_IFMT) == AE_IFREG;
    }

    bool isDir() @trusted {
        return (archive_entry_filetype(_entry) & AE_IFMT) == AE_IFDIR;
    }

    bool isSymlink() @trusted {
        return (archive_entry_filetype(_entry) & AE_IFMT) == AE_IFLNK;
    }

    uint filetype() @trusted {
        return archive_entry_filetype(_entry);
    }

    void filetype(uint ft) @trusted {
        archive_entry_set_filetype(_entry, ft);
    }

    // -- Properties: permissions --

    uint permissions() @trusted {
        return archive_entry_perm(_entry);
    }

    void permissions(uint p) @trusted {
        archive_entry_set_perm(_entry, p);
    }

    uint mode() @trusted {
        return archive_entry_mode(_entry);
    }

    void mode(uint m) @trusted {
        archive_entry_set_mode(_entry, m);
    }

    // -- Properties: time --

    SysTime mtime() @trusted {
        auto t = archive_entry_mtime(_entry);
        auto nsec = archive_entry_mtime_nsec(_entry);
        return SysTime(
            unixTimeToStdTime(t) + nsec / 100,
            UTC()
        );
    }

    void mtime(SysTime t) @trusted {
        auto unix = t.toUnixTime();
        auto frac = (t.stdTime - unixTimeToStdTime(unix));
        archive_entry_set_mtime(_entry, unix, cast(c_long)(frac * 100));
    }

    // -- Properties: links --

    string symlinkTarget() @trusted {
        auto p = archive_entry_symlink(_entry);
        return p is null ? null : p.fromStringz.idup;
    }

    void symlinkTarget(string target) @trusted {
        import std.string : toStringz;
        archive_entry_set_symlink_utf8(_entry, target.toStringz);
    }

    string hardlinkTarget() @trusted {
        auto p = archive_entry_hardlink(_entry);
        return p is null ? null : p.fromStringz.idup;
    }

    void hardlinkTarget(string target) @trusted {
        import std.string : toStringz;
        archive_entry_set_hardlink_utf8(_entry, target.toStringz);
    }

    // -- Properties: uid/gid --

    long uid() @trusted { return archive_entry_uid(_entry); }
    void uid(long v) @trusted { archive_entry_set_uid(_entry, v); }

    long gid() @trusted { return archive_entry_gid(_entry); }
    void gid(long v) @trusted { archive_entry_set_gid(_entry, v); }

    string uname() @trusted {
        auto p = archive_entry_uname(_entry);
        return p is null ? null : p.fromStringz.idup;
    }

    string gname() @trusted {
        auto p = archive_entry_gname(_entry);
        return p is null ? null : p.fromStringz.idup;
    }

    // -- Raw handle --

    archive_entry* handle() @trusted { return _entry; }

    /// Clear and reuse this entry (only valid for owned entries).
    void clear() @trusted {
        if (_entry !is null)
            archive_entry_clear(_entry);
    }
}

private long unixTimeToStdTime(long unixTime) @safe pure nothrow @nogc {
    return (unixTime + 621_355_968_00L) * 10_000_000L;
}
