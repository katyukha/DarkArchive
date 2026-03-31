/// ZIP format structures and constants (PKWARE APPNOTE.TXT).
module darkarchive.formats.zip.types;

// -- Signatures --
enum uint ZIP_LOCAL_FILE_HEADER_SIG    = 0x04034b50; // "PK\x03\x04"
enum uint ZIP_CENTRAL_DIR_SIG         = 0x02014b50; // "PK\x01\x02"
enum uint ZIP_END_OF_CENTRAL_DIR_SIG  = 0x06054b50; // "PK\x05\x06"
enum uint ZIP_ZIP64_EOCD_SIG          = 0x06064b50;
enum uint ZIP_ZIP64_LOCATOR_SIG       = 0x07064b50;
enum uint ZIP_DATA_DESCRIPTOR_SIG     = 0x08074b50;

// -- Compression methods --
enum ushort ZIP_METHOD_STORE   = 0;
enum ushort ZIP_METHOD_DEFLATE = 8;

// -- Flags --
enum ushort ZIP_FLAG_DATA_DESCRIPTOR = 1 << 3;  // bit 3
enum ushort ZIP_FLAG_UTF8            = 1 << 11; // bit 11

// -- ZIP64 sentinel values --
enum uint   ZIP64_MAGIC_32 = 0xFFFFFFFF;
enum ushort ZIP64_MAGIC_16 = 0xFFFF;

// -- ZIP64 extra field header ID --
enum ushort ZIP64_EXTRA_FIELD_ID = 0x0001;

// -- Version made by / needed --
enum ushort ZIP_VERSION_NEEDED_DEFAULT = 20; // 2.0
enum ushort ZIP_VERSION_NEEDED_ZIP64   = 45; // 4.5
enum ushort ZIP_VERSION_MADE_BY        = 63; // 6.3, Unix
