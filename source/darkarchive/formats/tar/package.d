/// TAR format reader and writer.
module darkarchive.formats.tar;

public import darkarchive.formats.tar.types;
public import darkarchive.formats.tar.reader : TarReader, tarReader, tarGzReader;
public import darkarchive.formats.tar.writer : TarWriter, tarWriter, tarGzWriter, gzipCompress;

import darkarchive.datasource : ChunkReader, FileChunkSource, GzipRange, DelegateSink;
import darkarchive.gzip : GzipSink;

/// Concrete file-backed TAR reader (plain, no compression).
alias TarFileReader = TarReader!(ChunkReader!FileChunkSource);

/// Concrete file-backed TAR.GZ reader (gzip decompression layer included).
alias TarGzReader   = TarReader!(ChunkReader!(GzipRange!FileChunkSource));

/// Concrete file-backed TAR writer (plain, no compression).
alias TarFileWriter = TarWriter!DelegateSink;

/// Concrete file-backed TAR.GZ writer (gzip compression layer included).
alias TarGzWriter   = TarWriter!(GzipSink!DelegateSink);
