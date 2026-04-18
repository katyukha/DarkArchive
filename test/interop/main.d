/// Interoperability tests: cross-verify darkarchive with GNU tar, Info-ZIP, and Python.
///
/// Each test either:
///   - writes an archive with darkarchive, then verifies it with an external tool, or
///   - generates an archive with an external tool, then reads it with darkarchive.
///
/// Tests skip gracefully when the required tool is not installed.
/// Exit code is non-zero if any test fails.
module darkarchive.test.interop;

import std.stdio;
import std.process;
import std.file;
import std.path;
import std.string : strip;
import std.conv : to;
import std.format : format;
import std.algorithm : canFind;
import std.datetime.systime : SysTime, unixTimeToStdTime;
import std.datetime.date : DateTime;
import std.datetime.timezone : UTC;

import darkarchive;

alias WTar   = DarkArchiveWriter!(DarkArchiveFormat.tar);
alias WTarGz = DarkArchiveWriter!(DarkArchiveFormat.tarGz);
alias WZip   = DarkArchiveWriter!(DarkArchiveFormat.zip);
alias RTarGz = DarkArchiveReader!(DarkArchiveFormat.tarGz);
alias RZip   = DarkArchiveReader!(DarkArchiveFormat.zip);

// ── Minimal test framework ───────────────────────────────────────────────────

int _failures;

void check(bool cond, lazy string msg,
           string file = __FILE__, size_t line = __LINE__)
{
    if (!cond)
        throw new Exception(format!"%s (%s:%d)"(msg, file, line));
}

void checkEq(T)(T actual, T expected,
               string file = __FILE__, size_t line = __LINE__)
{
    if (actual != expected)
        throw new Exception(
            format!"expected %s, got %s (%s:%d)"(expected, actual, file, line));
}

enum Skip { yes }  // sentinel thrown to signal a skipped test

void runTest(string name, void delegate() body)
{
    write("  ");
    try {
        body();
        writefln("PASS  %s", name);
    } catch (Skip) {
        writefln("SKIP  %s", name);
    } catch (Exception e) {
        writefln("FAIL  %s\n        %s", name, e.msg);
        _failures++;
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Throw Skip if `tool` is not found on PATH.
void requireTool(string tool)
{
    version(Windows) throw new Skip();
    if (execute(["which", tool]).status != 0)
        throw new Skip();
}

/// Write a Python script to `dir/name` and return its path.
string writePy(string dir, string name, string code)
{
    auto p = buildPath(dir, name);
    std.file.write(p, code);
    return p;
}

/// Run a command; throw on non-zero exit.
void run(string[] cmd, string context = "")
{
    auto r = execute(cmd);
    if (r.status != 0)
        throw new Exception(
            (context.length ? context ~ ": " : "") ~
            cmd[0] ~ " failed:\n" ~ r.output.strip);
}

// ── Tests: darkarchive writes → external tool reads ─────────────────────────

void testOurTarReadableBySystemTar(string tmp)
{
    requireTool("tar");

    auto arch = buildPath(tmp, "our.tar.gz");
    auto exDir = buildPath(tmp, "ex-tar");
    mkdirRecurse(exDir);

    WTarGz(arch)
        .addBuffer("hello.txt",  cast(const(ubyte)[]) "hello from darkarchive\n")
        .addBuffer("sub/b.txt",  cast(const(ubyte)[]) "nested file\n")
        .addDirectory("emptydir")
        .finish();

    // Listing
    auto list = execute(["tar", "-tzf", arch]);
    check(list.status == 0, "tar -tzf failed: " ~ list.output.strip);
    check(list.output.canFind("hello.txt"), "hello.txt missing from tar listing");
    check(list.output.canFind("sub/b.txt"), "sub/b.txt missing from tar listing");
    check(list.output.canFind("emptydir"),  "emptydir missing from tar listing");

    // Extract and verify content
    run(["tar", "-xzf", arch, "-C", exDir], "tar -xzf");
    checkEq(readText(buildPath(exDir, "hello.txt")), "hello from darkarchive\n");
    checkEq(readText(buildPath(exDir, "sub", "b.txt")), "nested file\n");
}

void testOurZipReadableByUnzip(string tmp)
{
    requireTool("unzip");

    auto arch = buildPath(tmp, "our.zip");
    WZip(arch)
        .addBuffer("hello.txt",  cast(const(ubyte)[]) "hello from darkarchive\n")
        .addBuffer("data/x.bin", cast(const(ubyte)[]) "binary\n")
        .addDirectory("emptydir")
        .finish();

    // -t verifies CRCs without extracting
    auto r = execute(["unzip", "-t", arch]);
    check(r.status == 0, "unzip -t failed:\n" ~ r.output.strip);
}

void testOurZipReadableByPython(string tmp)
{
    requireTool("python3");

    auto arch = buildPath(tmp, "our-py.zip");
    WZip(arch)
        .addBuffer("greeting.txt",  cast(const(ubyte)[]) "Hello from D!\n")
        .addBuffer("data/info.txt", cast(const(ubyte)[]) "archive info\n")
        .addDirectory("emptydir")
        .finish();

    auto script = writePy(tmp, "verify-zip.py", format!`
import zipfile, sys
with zipfile.ZipFile(sys.argv[1]) as zf:
    names = zf.namelist()
    assert "greeting.txt"  in names, f"missing greeting.txt: {names}"
    assert "data/info.txt" in names, f"missing data/info.txt: {names}"
    assert "emptydir/"     in names, f"missing emptydir/: {names}"
    assert zf.read("greeting.txt")  == b"Hello from D!\n",  "content mismatch"
    assert zf.read("data/info.txt") == b"archive info\n",   "content mismatch"
    # Triggers CRC verification for every entry
    for info in zf.infolist():
        zf.read(info.filename)
print("ok")
`());
    auto r = execute(["python3", script, arch]);
    check(r.status == 0, "python3 ZIP verify failed:\n" ~ r.output.strip);
    check(r.output.strip == "ok", "unexpected output: " ~ r.output.strip);
}

void testOurTarGzReadableByPython(string tmp)
{
    requireTool("python3");

    auto arch = buildPath(tmp, "our-py.tar.gz");
    WTarGz(arch)
        .addBuffer("a.txt", cast(const(ubyte)[]) "content-a\n")
        .addBuffer("b.txt", cast(const(ubyte)[]) "content-b\n")
        .addDirectory("subdir")
        .finish();

    auto script = writePy(tmp, "verify-tar.py", format!`
import tarfile, sys
with tarfile.open(sys.argv[1], 'r:gz') as tf:
    names = tf.getnames()
    assert "a.txt"  in names, f"missing a.txt: {names}"
    assert "b.txt"  in names, f"missing b.txt: {names}"
    assert "subdir" in names, f"missing subdir: {names}"
    assert tf.extractfile("a.txt").read() == b"content-a\n", "a.txt content mismatch"
    assert tf.extractfile("b.txt").read() == b"content-b\n", "b.txt content mismatch"
print("ok")
`());
    auto r = execute(["python3", script, arch]);
    check(r.status == 0, "python3 TAR verify failed:\n" ~ r.output.strip);
    check(r.output.strip == "ok", "unexpected output: " ~ r.output.strip);
}

// ── Tests: external tool writes → darkarchive reads ─────────────────────────

void testGnuTarPaxMtimeFractional(string tmp)
{
    requireTool("tar");
    requireTool("python3");

    // Python sets a fractional mtime that GNU tar will encode in the PAX header.
    // mtime = 1710506096.123456716 → PAX string "1710506096.123456716"
    // Our reader must parse this to hnsec precision (7 digits): +1_234_567 hnsecs
    auto srcDir = buildPath(tmp, "pax-src");
    auto arch   = buildPath(tmp, "pax.tar.gz");
    mkdirRecurse(srcDir);

    run(["python3", "-c", format!`
import os
with open('%s/hello.txt', 'w') as f: f.write('pax mtime test\n')
os.utime('%s/hello.txt', (1710506096.123456716, 1710506096.123456716))
`(srcDir, srcDir)], "set mtime");

    run(["tar", "--format=pax", "-czf", arch, "-C", srcDir, "hello.txt"],
        "tar create");

    bool found;
    auto reader = tarGzReader(arch);
    scope(exit) reader.close();
    foreach (entry; reader.entries) {
        if (entry.pathname == "hello.txt") {
            // PAX "1710506096.123456716" → first 7 fractional digits = 1_234_567 hnsecs
            auto expected = SysTime(unixTimeToStdTime(1710506096L) + 1_234_567L, UTC());
            checkEq(entry.mtime, expected);
            found = true;
        }
    }
    check(found, "hello.txt not found in GNU tar PAX archive");
}

void testInfoZipUtMtimeExact(string tmp)
{
    requireTool("zip");
    requireTool("python3");

    // Odd second (57s): DOS time rounds to 58s; UT extra field stores exact 57s.
    // We verify that our reader uses the UT field, not the DOS time.
    auto srcDir = buildPath(tmp, "zip-src");
    auto arch   = buildPath(tmp, "infozip.zip");
    mkdirRecurse(srcDir);

    run(["python3", "-c", format!`
import os
with open('%s/hello.txt', 'w') as f: f.write('ut mtime test\n')
os.utime('%s/hello.txt', (1710506097, 1710506097))
`(srcDir, srcDir)], "set mtime");

    // -j: junk directory prefix so the entry name is just "hello.txt"
    run(["zip", "-j", arch, buildPath(srcDir, "hello.txt")], "zip create");

    bool found;
    auto reader = RZip(arch);
    scope(exit) reader.close();
    foreach (entry; reader.entries) {
        if (entry.pathname == "hello.txt") {
            // UT field: exact Unix mtime 1710506097 = 2024-03-15T12:34:57 UTC
            // DOS time would give :58 (rounded up from 57s)
            auto expected = SysTime(DateTime(2024, 3, 15, 12, 34, 57), UTC());
            checkEq(entry.mtime, expected);
            found = true;
        }
    }
    check(found, "hello.txt not found in Info-ZIP archive");
}

void testPythonTarfileUtf8(string tmp)
{
    requireTool("python3");

    auto arch = buildPath(tmp, "py-utf8.tar.gz");
    auto script = writePy(tmp, "make-utf8-tar.py", format!`
import tarfile, io
with tarfile.open('%s', 'w:gz') as tf:
    for name, data in [
        ('cafe\u0301.txt',    b'coffee'),
        ('\u65e5\u672c\u8a9e.txt', b'japanese'),
        ('sub/\xdcni\xf6c.txt',   b'unicode'),
    ]:
        info = tarfile.TarInfo(name=name)
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
print("ok")
`(arch));
    auto r = execute(["python3", script]);
    check(r.status == 0, "python3 create failed:\n" ~ r.output.strip);

    string[] names;
    auto reader = tarGzReader(arch);
    scope(exit) reader.close();
    foreach (entry; reader.entries)
        names ~= entry.pathname;

    check(names.canFind("café.txt"),      "missing café.txt");
    check(names.canFind("日本語.txt"),     "missing 日本語.txt");
    check(names.canFind("sub/Üniöc.txt"), "missing sub/Üniöc.txt");
}

void testPythonZipfileDeflate(string tmp)
{
    requireTool("python3");

    auto arch = buildPath(tmp, "py-deflate.zip");
    auto script = writePy(tmp, "make-deflate-zip.py", format!`
import zipfile
with zipfile.ZipFile('%s', 'w', zipfile.ZIP_DEFLATED) as zf:
    zf.writestr('compressed.txt', 'hello compressed world\n' * 100)
    zf.writestr('small.txt', 'small')
print("ok")
`(arch));
    auto r = execute(["python3", script]);
    check(r.status == 0, "python3 create failed:\n" ~ r.output.strip);

    bool foundComp, foundSmall;
    auto reader = RZip(arch);
    scope(exit) reader.close();
    size_t i;
    foreach (entry; reader.entries) {
        if (entry.pathname == "compressed.txt") {
            auto data = reader.readText(i);
            check(data.length == ("hello compressed world\n" ~ "").length * 100,
                  "compressed.txt length mismatch");
            foundComp = true;
        } else if (entry.pathname == "small.txt") {
            checkEq(reader.readText(i), "small");
            foundSmall = true;
        }
        i++;
    }
    check(foundComp,  "compressed.txt not found");
    check(foundSmall, "small.txt not found");
}

// ── main ─────────────────────────────────────────────────────────────────────

int main()
{
    auto tmp = buildPath(tempDir(), "darkarchive-interop");
    if (tmp.exists) rmdirRecurse(tmp);
    mkdirRecurse(tmp);
    scope(exit) try { rmdirRecurse(tmp); } catch (Exception) {}

    writeln("Interop tests");
    writeln("=============");

    runTest("our TAR.GZ readable by system tar",
            () => testOurTarReadableBySystemTar(tmp));
    runTest("our ZIP readable by unzip (-t)",
            () => testOurZipReadableByUnzip(tmp));
    runTest("our ZIP readable by Python zipfile",
            () => testOurZipReadableByPython(tmp));
    runTest("our TAR.GZ readable by Python tarfile",
            () => testOurTarGzReadableByPython(tmp));
    runTest("GNU tar PAX mtime has sub-second precision",
            () => testGnuTarPaxMtimeFractional(tmp));
    runTest("Info-ZIP UT extra field gives exact mtime",
            () => testInfoZipUtMtimeExact(tmp));
    runTest("Python tarfile UTF-8 filenames round-trip",
            () => testPythonTarfileUtf8(tmp));
    runTest("Python zipfile deflate read-back",
            () => testPythonZipfileDeflate(tmp));

    writeln();
    if (_failures == 0) {
        writeln("All tests passed.");
        return 0;
    }
    writefln("%d test(s) FAILED.", _failures);
    return 1;
}
