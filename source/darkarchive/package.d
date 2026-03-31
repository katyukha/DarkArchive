module darkarchive;

public import darkarchive.archive : DarkArchiveReader, DarkArchiveWriter,
                                     DarkArchiveFormat, DarkArchiveFilter, DarkExtractFlags;
public import darkarchive.entry : DarkArchiveEntry;
public import darkarchive.exception : DarkArchiveException;

/// Returns libarchive version string.
string getLibArchiveVersion() @trusted {
    import std.string : fromStringz;
    import darkarchive.lib : archive_version_string;
    auto p = archive_version_string();
    return p is null ? null : p.fromStringz.idup;
}
