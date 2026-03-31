/// Shared C types, constants, enums, and callback typedefs for libarchive bindings.
module darkarchive.lib.types;

public import core.stdc.time;
public import core.stdc.stdio;
import core.stdc.config : c_long;

// ---------------------------------------------------------------------------
// Platform-dependent type aliases matching libarchive's la_* types
// ---------------------------------------------------------------------------

alias la_int64_t  = long;
alias la_uint64_t = ulong;
alias la_ssize_t  = c_long;  // ssize_t on most platforms

// ---------------------------------------------------------------------------
// Opaque structs
// ---------------------------------------------------------------------------

struct archive;
struct archive_entry;
struct archive_entry_linkresolver;
struct archive_acl;

// ---------------------------------------------------------------------------
// Return codes
// ---------------------------------------------------------------------------

enum ARCHIVE_EOF    =   1;
enum ARCHIVE_OK     =   0;
enum ARCHIVE_RETRY  = -10;
enum ARCHIVE_WARN   = -20;
enum ARCHIVE_FAILED = -25;
enum ARCHIVE_FATAL  = -30;

// ---------------------------------------------------------------------------
// Filter/compression codes (ARCHIVE_FILTER_*)
// ---------------------------------------------------------------------------

enum ARCHIVE_FILTER_NONE     = 0;
enum ARCHIVE_FILTER_GZIP     = 1;
enum ARCHIVE_FILTER_BZIP2    = 2;
enum ARCHIVE_FILTER_COMPRESS = 3;
enum ARCHIVE_FILTER_PROGRAM  = 4;
enum ARCHIVE_FILTER_LZMA     = 5;
enum ARCHIVE_FILTER_XZ       = 6;
enum ARCHIVE_FILTER_UU       = 7;
enum ARCHIVE_FILTER_RPM      = 8;
enum ARCHIVE_FILTER_LZIP     = 9;
enum ARCHIVE_FILTER_LRZIP    = 10;
enum ARCHIVE_FILTER_LZOP     = 11;
enum ARCHIVE_FILTER_GRZIP    = 12;
enum ARCHIVE_FILTER_LZ4      = 13;
enum ARCHIVE_FILTER_ZSTD     = 14;

// ---------------------------------------------------------------------------
// Format codes (ARCHIVE_FORMAT_*)
// ---------------------------------------------------------------------------

enum ARCHIVE_FORMAT_BASE_MASK           = 0xff0000;
enum ARCHIVE_FORMAT_CPIO                = 0x10000;
enum ARCHIVE_FORMAT_CPIO_POSIX         = (ARCHIVE_FORMAT_CPIO | 1);
enum ARCHIVE_FORMAT_CPIO_BIN_LE       = (ARCHIVE_FORMAT_CPIO | 2);
enum ARCHIVE_FORMAT_CPIO_BIN_BE       = (ARCHIVE_FORMAT_CPIO | 3);
enum ARCHIVE_FORMAT_CPIO_SVR4_NOCRC   = (ARCHIVE_FORMAT_CPIO | 4);
enum ARCHIVE_FORMAT_CPIO_SVR4_CRC     = (ARCHIVE_FORMAT_CPIO | 5);
enum ARCHIVE_FORMAT_CPIO_AFIO_LARGE   = (ARCHIVE_FORMAT_CPIO | 6);
enum ARCHIVE_FORMAT_CPIO_PWB          = (ARCHIVE_FORMAT_CPIO | 7);
enum ARCHIVE_FORMAT_SHAR               = 0x20000;
enum ARCHIVE_FORMAT_SHAR_BASE         = (ARCHIVE_FORMAT_SHAR | 1);
enum ARCHIVE_FORMAT_SHAR_DUMP         = (ARCHIVE_FORMAT_SHAR | 2);
enum ARCHIVE_FORMAT_TAR                = 0x30000;
enum ARCHIVE_FORMAT_TAR_USTAR         = (ARCHIVE_FORMAT_TAR | 1);
enum ARCHIVE_FORMAT_TAR_PAX_INTERCHANGE = (ARCHIVE_FORMAT_TAR | 2);
enum ARCHIVE_FORMAT_TAR_PAX_RESTRICTED = (ARCHIVE_FORMAT_TAR | 3);
enum ARCHIVE_FORMAT_TAR_GNUTAR        = (ARCHIVE_FORMAT_TAR | 4);
enum ARCHIVE_FORMAT_ISO9660            = 0x40000;
enum ARCHIVE_FORMAT_ISO9660_ROCKRIDGE = (ARCHIVE_FORMAT_ISO9660 | 1);
enum ARCHIVE_FORMAT_ZIP                = 0x50000;
enum ARCHIVE_FORMAT_EMPTY              = 0x60000;
enum ARCHIVE_FORMAT_AR                 = 0x70000;
enum ARCHIVE_FORMAT_AR_GNU            = (ARCHIVE_FORMAT_AR | 1);
enum ARCHIVE_FORMAT_AR_BSD            = (ARCHIVE_FORMAT_AR | 2);
enum ARCHIVE_FORMAT_MTREE              = 0x80000;
enum ARCHIVE_FORMAT_RAW                = 0x90000;
enum ARCHIVE_FORMAT_XAR                = 0xA0000;
enum ARCHIVE_FORMAT_LHA                = 0xB0000;
enum ARCHIVE_FORMAT_CAB                = 0xC0000;
enum ARCHIVE_FORMAT_RAR                = 0xD0000;
enum ARCHIVE_FORMAT_7ZIP               = 0xE0000;
enum ARCHIVE_FORMAT_WARC               = 0xF0000;
enum ARCHIVE_FORMAT_RAR_V5             = 0x100000;

// ---------------------------------------------------------------------------
// Read format capability codes
// ---------------------------------------------------------------------------

enum ARCHIVE_READ_FORMAT_CAPS_NONE             = 0;
enum ARCHIVE_READ_FORMAT_CAPS_ENCRYPT_DATA     = (1 << 0);
enum ARCHIVE_READ_FORMAT_CAPS_ENCRYPT_METADATA = (1 << 1);

// ---------------------------------------------------------------------------
// Encryption detection codes
// ---------------------------------------------------------------------------

enum ARCHIVE_READ_FORMAT_ENCRYPTION_UNSUPPORTED = -2;
enum ARCHIVE_READ_FORMAT_ENCRYPTION_DONT_KNOW   = -1;

// ---------------------------------------------------------------------------
// Extract flags (ARCHIVE_EXTRACT_*)
// ---------------------------------------------------------------------------

enum ARCHIVE_EXTRACT_OWNER                  = 0x0001;
enum ARCHIVE_EXTRACT_PERM                   = 0x0002;
enum ARCHIVE_EXTRACT_TIME                   = 0x0004;
enum ARCHIVE_EXTRACT_NO_OVERWRITE           = 0x0008;
enum ARCHIVE_EXTRACT_UNLINK                 = 0x0010;
enum ARCHIVE_EXTRACT_ACL                    = 0x0020;
enum ARCHIVE_EXTRACT_FFLAGS                 = 0x0040;
enum ARCHIVE_EXTRACT_XATTR                  = 0x0080;
enum ARCHIVE_EXTRACT_SECURE_SYMLINKS        = 0x0100;
enum ARCHIVE_EXTRACT_SECURE_NODOTDOT        = 0x0200;
enum ARCHIVE_EXTRACT_NO_AUTODIR             = 0x0400;
enum ARCHIVE_EXTRACT_NO_OVERWRITE_NEWER     = 0x0800;
enum ARCHIVE_EXTRACT_SPARSE                 = 0x1000;
enum ARCHIVE_EXTRACT_MAC_METADATA           = 0x2000;
enum ARCHIVE_EXTRACT_NO_HFS_COMPRESSION     = 0x4000;
enum ARCHIVE_EXTRACT_HFS_COMPRESSION_FORCED = 0x8000;
enum ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS = 0x10000;
enum ARCHIVE_EXTRACT_CLEAR_NOCHANGE_FFLAGS  = 0x20000;
enum ARCHIVE_EXTRACT_SAFE_WRITES            = 0x40000;

// ---------------------------------------------------------------------------
// Read-disk behavior flags (ARCHIVE_READDISK_*)
// ---------------------------------------------------------------------------

enum ARCHIVE_READDISK_RESTORE_ATIME        = 0x0001;
enum ARCHIVE_READDISK_HONOR_NODUMP         = 0x0002;
enum ARCHIVE_READDISK_MAC_COPYFILE         = 0x0004;
enum ARCHIVE_READDISK_NO_TRAVERSE_MOUNTS   = 0x0008;
enum ARCHIVE_READDISK_NO_XATTR             = 0x0010;
enum ARCHIVE_READDISK_NO_ACL               = 0x0020;
enum ARCHIVE_READDISK_NO_FFLAGS            = 0x0040;
enum ARCHIVE_READDISK_NO_SPARSE            = 0x0080;

// ---------------------------------------------------------------------------
// File-type constants (from archive_entry.h, octal values)
// ---------------------------------------------------------------------------

import std.conv : octal;
enum AE_IFMT   = octal!170000;
enum AE_IFREG  = octal!100000;
enum AE_IFLNK  = octal!120000;
enum AE_IFSOCK = octal!140000;
enum AE_IFCHR  = octal!20000;
enum AE_IFBLK  = octal!60000;
enum AE_IFDIR  = octal!40000;
enum AE_IFIFO  = octal!10000;

// ---------------------------------------------------------------------------
// Symlink type constants
// ---------------------------------------------------------------------------

enum AE_SYMLINK_TYPE_UNDEFINED = 0;
enum AE_SYMLINK_TYPE_FILE      = 1;
enum AE_SYMLINK_TYPE_DIRECTORY = 2;

// ---------------------------------------------------------------------------
// Entry digest types
// ---------------------------------------------------------------------------

enum ARCHIVE_ENTRY_DIGEST_MD5    = 0x00000001;
enum ARCHIVE_ENTRY_DIGEST_RMD160 = 0x00000002;
enum ARCHIVE_ENTRY_DIGEST_SHA1   = 0x00000003;
enum ARCHIVE_ENTRY_DIGEST_SHA256 = 0x00000004;
enum ARCHIVE_ENTRY_DIGEST_SHA384 = 0x00000005;
enum ARCHIVE_ENTRY_DIGEST_SHA512 = 0x00000006;

// ---------------------------------------------------------------------------
// Callback typedefs
// ---------------------------------------------------------------------------

extern(C) nothrow {
    alias archive_read_callback      = la_ssize_t function(archive*, void*, const(void)**);
    alias archive_write_callback     = la_ssize_t function(archive*, void*, const(void)*, size_t);
    alias archive_open_callback      = int function(archive*, void*);
    alias archive_close_callback     = int function(archive*, void*);
    alias archive_free_callback      = int function(archive*, void*);
    alias archive_skip_callback      = la_int64_t function(archive*, void*, la_int64_t);
    alias archive_seek_callback      = la_int64_t function(archive*, void*, la_int64_t, int);
    alias archive_switch_callback    = int function(archive*, void*, void*);
    alias archive_passphrase_callback = const(char)* function(archive*, void*);
}
