/// TAR format structures and constants (POSIX.1-2001 ustar + pax).
module darkarchive.formats.tar.types;

// -- Header size --
enum TAR_BLOCK_SIZE = 512;

// -- Type flags --
enum TAR_TYPE_FILE    = '0';
enum TAR_TYPE_FILE_ALT = '\0';  // old V7 regular file
enum TAR_TYPE_HARDLINK = '1';
enum TAR_TYPE_SYMLINK  = '2';
enum TAR_TYPE_DIR      = '5';
enum TAR_TYPE_PAX_EXTENDED = 'x';  // pax extended header for next entry
enum TAR_TYPE_PAX_GLOBAL   = 'g';  // pax global extended header

// -- Magic --
enum string TAR_MAGIC = "ustar";  // 6 bytes including null
