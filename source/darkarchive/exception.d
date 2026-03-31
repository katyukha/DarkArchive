module darkarchive.exception;

import darkarchive.lib;

class DarkArchiveException : Exception {
    int archiveErrno;

    this(string msg, string file = __FILE__, size_t line = __LINE__) {
        super(msg, file, line);
    }

    this(string msg, int archiveErrno, string file = __FILE__, size_t line = __LINE__) {
        this.archiveErrno = archiveErrno;
        super(msg, file, line);
    }
}

/// Check libarchive return code. Throws on FAILED/FATAL, logs on WARN.
void enforceArchiveOk(archive* a, int ret, string context = null) @trusted {
    import std.format : format;
    import std.string : fromStringz;

    if (ret < ARCHIVE_WARN) {
        // ARCHIVE_FAILED or ARCHIVE_FATAL
        string errMsg = "unknown error";
        auto errPtr = archive_error_string(a);
        if (errPtr !is null)
            errMsg = errPtr.fromStringz.idup;
        auto msg = context
            ? "%s: %s".format(context, errMsg)
            : errMsg;
        throw new DarkArchiveException(msg, archive_errno(a));
    }

    version(DarkArchiveEnableLogger) {
        if (ret < ARCHIVE_OK) {
            import std.experimental.logger : warning;
            string errMsg = "unknown warning";
            auto errPtr = archive_error_string(a);
            if (errPtr !is null)
                errMsg = errPtr.fromStringz.idup;
            warning(context
                ? "%s: warning: %s".format(context, errMsg)
                : "warning: %s".format(errMsg));
        }
    }
}
