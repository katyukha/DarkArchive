# DarkArchive

*Born in the darkest and deepest place of nothing.*

A pure D library for reading and writing archive formats. No C dependencies. No locale issues. No temporary files. Just darkn magic that handles archives.

## Warning

> *These aren't the droids you're looking for.*

This is a **development version**. Not a release candidate. Not beta. Not even alpha. The API will change. Things will break.

If you use this in production, you do so at your own peril. You have been warned.

## Formats

- **ZIP** — read/write, deflate & store, ZIP64, UTF-8 filenames, symlinks
- **TAR** — read/write, ustar & pax extended headers, UTF-8 pathnames
- **TAR.GZ** — read/write, streaming gzip decompression

## What lurks within

- Streaming I/O — handles archives larger than available memory
- Zero system dependencies — only `std.zlib` from Phobos

## License

MPL-2.0
