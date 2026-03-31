/// Dynamic loader for libarchive. On DarkArchiveDynamic, loads the shared
/// library at module startup via bindbc-loader.
module darkarchive.lib;

private import std.format : format;
private import std.string : join, fromStringz;
private import std.algorithm : map;

public import darkarchive.lib.libarchive;
public import darkarchive.lib.libarchive_entry;
public import darkarchive.lib.types;

version(DarkArchiveDynamic) {
    private import bindbc.loader;
    private import bindbc.common : Version;

    private SharedLib lib;

    private enum supportedLibNames = mixin(makeLibPaths(
        names: ["archive", "archive.13"],
        platformPaths: [
            "OSX": [
                "/usr/local/opt/libarchive/lib/",
                "/opt/homebrew/opt/libarchive/lib/",
            ],
        ]
    ));

    bool loadDarkArchive(in string libname) {
        lib = bindbc.loader.load(libname.ptr);
        if (lib == bindbc.loader.invalidHandle) {
            return false;
        }

        auto err_count = bindbc.loader.errorCount;
        darkarchive.lib.libarchive.bindModuleSymbols(lib);
        if (bindbc.loader.errorCount != err_count)
            return false;

        darkarchive.lib.libarchive_entry.bindModuleSymbols(lib);
        if (bindbc.loader.errorCount != err_count)
            return false;

        return true;
    }

    bool loadDarkArchive() {
        foreach (libname; supportedLibNames)
            if (loadDarkArchive(libname))
                return true;
        return false;
    }

    shared static this() {
        auto err_count_start = bindbc.loader.errorCount;
        bool load_status = loadDarkArchive;
        if (!load_status) {
            auto errors = bindbc.loader.errors[err_count_start .. bindbc.loader.errorCount]
                .map!((e) => "%s: %s".format(e.error.fromStringz.idup, e.message.fromStringz.idup))
                .join(",\n");
            assert(0, "Cannot load libarchive library! Errors: %s".format(errors));
        }
    }
}
