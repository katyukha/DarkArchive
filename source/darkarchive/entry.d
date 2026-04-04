module darkarchive.entry;

import std.datetime.systime : SysTime;

/// Type of archive entry.
enum EntryType {
    file,
    directory,
    symlink,
    hardlink,  /// TAR hard link (typeflag '1') — links to another entry in the same archive
}

/// Archive entry metadata. Plain value struct — fully copyable, no C pointers.
struct DarkArchiveEntry {
    string pathname;
    long size = -1;           // -1 if unknown
    uint permissions;         // POSIX mode bits (e.g., octal!644)
    SysTime mtime;
    EntryType type = EntryType.file;
    string symlinkTarget;     // non-null for symlinks
    long uid;
    long gid;
    string uname;
    string gname;

    bool isFile() const { return type == EntryType.file; }
    bool isDir() const { return type == EntryType.directory; }
    bool isSymlink() const { return type == EntryType.symlink; }
    bool isHardlink() const { return type == EntryType.hardlink; }
}
