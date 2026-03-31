/// D bindings for libarchive's archive.h, using bindbc-common codegen.
module darkarchive.lib.libarchive;

private import bindbc.common.codegen : joinFnBinds, FnBind;
public import darkarchive.lib.types;

enum staticBinding = () {
    version(BindBC_Static)          return true;
    else version(DarkArchiveStatic) return true;
    else return false;
}();

mixin(joinFnBinds!staticBinding((){
    FnBind[] ret = [

        // -- Version info --
        {q{int}, q{archive_version_number}},
        {q{const(char)*}, q{archive_version_string}},
        {q{const(char)*}, q{archive_version_details}},
        {q{const(char)*}, q{archive_zlib_version}},
        {q{const(char)*}, q{archive_liblzma_version}},
        {q{const(char)*}, q{archive_bzlib_version}},
        {q{const(char)*}, q{archive_liblz4_version}},
        {q{const(char)*}, q{archive_libzstd_version}},

        // -- Archive read: new --
        {q{archive*}, q{archive_read_new}},

        // -- Archive read: support filter --
        {q{int}, q{archive_read_support_filter_all}, q{archive*}},
        {q{int}, q{archive_read_support_filter_by_code}, q{archive*, int}},
        {q{int}, q{archive_read_support_filter_bzip2}, q{archive*}},
        {q{int}, q{archive_read_support_filter_compress}, q{archive*}},
        {q{int}, q{archive_read_support_filter_gzip}, q{archive*}},
        {q{int}, q{archive_read_support_filter_grzip}, q{archive*}},
        {q{int}, q{archive_read_support_filter_lrzip}, q{archive*}},
        {q{int}, q{archive_read_support_filter_lz4}, q{archive*}},
        {q{int}, q{archive_read_support_filter_lzip}, q{archive*}},
        {q{int}, q{archive_read_support_filter_lzma}, q{archive*}},
        {q{int}, q{archive_read_support_filter_lzop}, q{archive*}},
        {q{int}, q{archive_read_support_filter_none}, q{archive*}},
        {q{int}, q{archive_read_support_filter_program}, q{archive*, const(char)*}},
        {q{int}, q{archive_read_support_filter_program_signature}, q{archive*, const(char)*, const(void)*, size_t}},
        {q{int}, q{archive_read_support_filter_rpm}, q{archive*}},
        {q{int}, q{archive_read_support_filter_uu}, q{archive*}},
        {q{int}, q{archive_read_support_filter_xz}, q{archive*}},
        {q{int}, q{archive_read_support_filter_zstd}, q{archive*}},

        // -- Archive read: support format --
        {q{int}, q{archive_read_support_format_7zip}, q{archive*}},
        {q{int}, q{archive_read_support_format_all}, q{archive*}},
        {q{int}, q{archive_read_support_format_ar}, q{archive*}},
        {q{int}, q{archive_read_support_format_by_code}, q{archive*, int}},
        {q{int}, q{archive_read_support_format_cab}, q{archive*}},
        {q{int}, q{archive_read_support_format_cpio}, q{archive*}},
        {q{int}, q{archive_read_support_format_empty}, q{archive*}},
        {q{int}, q{archive_read_support_format_gnutar}, q{archive*}},
        {q{int}, q{archive_read_support_format_iso9660}, q{archive*}},
        {q{int}, q{archive_read_support_format_lha}, q{archive*}},
        {q{int}, q{archive_read_support_format_mtree}, q{archive*}},
        {q{int}, q{archive_read_support_format_rar}, q{archive*}},
        {q{int}, q{archive_read_support_format_rar5}, q{archive*}},
        {q{int}, q{archive_read_support_format_raw}, q{archive*}},
        {q{int}, q{archive_read_support_format_tar}, q{archive*}},
        {q{int}, q{archive_read_support_format_warc}, q{archive*}},
        {q{int}, q{archive_read_support_format_xar}, q{archive*}},
        {q{int}, q{archive_read_support_format_zip}, q{archive*}},
        {q{int}, q{archive_read_support_format_zip_streamable}, q{archive*}},
        {q{int}, q{archive_read_support_format_zip_seekable}, q{archive*}},

        // -- Archive read: format/filter setting --
        {q{int}, q{archive_read_set_format}, q{archive*, int}},
        {q{int}, q{archive_read_append_filter}, q{archive*, int}},
        {q{int}, q{archive_read_append_filter_program}, q{archive*, const(char)*}},
        {q{int}, q{archive_read_append_filter_program_signature}, q{archive*, const(char)*, const(void)*, size_t}},

        // -- Archive read: callbacks --
        {q{int}, q{archive_read_set_open_callback}, q{archive*, archive_open_callback}},
        {q{int}, q{archive_read_set_read_callback}, q{archive*, archive_read_callback}},
        {q{int}, q{archive_read_set_seek_callback}, q{archive*, archive_seek_callback}},
        {q{int}, q{archive_read_set_skip_callback}, q{archive*, archive_skip_callback}},
        {q{int}, q{archive_read_set_close_callback}, q{archive*, archive_close_callback}},
        {q{int}, q{archive_read_set_switch_callback}, q{archive*, archive_switch_callback}},
        {q{int}, q{archive_read_set_callback_data}, q{archive*, void*}},
        {q{int}, q{archive_read_set_callback_data2}, q{archive*, void*, uint}},
        {q{int}, q{archive_read_add_callback_data}, q{archive*, void*, uint}},
        {q{int}, q{archive_read_append_callback_data}, q{archive*, void*}},
        {q{int}, q{archive_read_prepend_callback_data}, q{archive*, void*}},

        // -- Archive read: open --
        {q{int}, q{archive_read_open1}, q{archive*}},
        {q{int}, q{archive_read_open}, q{archive*, void*, archive_open_callback, archive_read_callback, archive_close_callback}},
        {q{int}, q{archive_read_open2}, q{archive*, void*, archive_open_callback, archive_read_callback, archive_skip_callback, archive_close_callback}},
        {q{int}, q{archive_read_open_filename}, q{archive*, const(char)*, size_t}},
        {q{int}, q{archive_read_open_memory}, q{archive*, const(void)*, size_t}},
        {q{int}, q{archive_read_open_memory2}, q{archive*, const(void)*, size_t, size_t}},
        {q{int}, q{archive_read_open_fd}, q{archive*, int, size_t}},
        {q{int}, q{archive_read_open_FILE}, q{archive*, FILE*}},

        // -- Archive read: iteration/data --
        {q{int}, q{archive_read_next_header}, q{archive*, archive_entry**}},
        {q{int}, q{archive_read_next_header2}, q{archive*, archive_entry*}},
        {q{la_int64_t}, q{archive_read_header_position}, q{archive*}},
        {q{int}, q{archive_read_has_encrypted_entries}, q{archive*}},
        {q{int}, q{archive_read_format_capabilities}, q{archive*}},
        {q{la_ssize_t}, q{archive_read_data}, q{archive*, void*, size_t}},
        {q{la_int64_t}, q{archive_seek_data}, q{archive*, la_int64_t, int}},
        {q{int}, q{archive_read_data_block}, q{archive*, const(void)**, size_t*, la_int64_t*}},
        {q{int}, q{archive_read_data_skip}, q{archive*}},
        {q{int}, q{archive_read_data_into_fd}, q{archive*, int}},

        // -- Archive read: options --
        {q{int}, q{archive_read_set_format_option}, q{archive*, const(char)*, const(char)*, const(char)*}},
        {q{int}, q{archive_read_set_filter_option}, q{archive*, const(char)*, const(char)*, const(char)*}},
        {q{int}, q{archive_read_set_option}, q{archive*, const(char)*, const(char)*, const(char)*}},
        {q{int}, q{archive_read_set_options}, q{archive*, const(char)*}},

        // -- Archive read: passphrase --
        {q{int}, q{archive_read_add_passphrase}, q{archive*, const(char)*}},
        {q{int}, q{archive_read_set_passphrase_callback}, q{archive*, void*, archive_passphrase_callback}},

        // -- Archive read: extract --
        {q{int}, q{archive_read_extract}, q{archive*, archive_entry*, int}},
        {q{int}, q{archive_read_extract2}, q{archive*, archive_entry*, archive*}},
        {q{void}, q{archive_read_extract_set_skip_file}, q{archive*, la_int64_t, la_int64_t}},

        // -- Archive read: close/free --
        {q{int}, q{archive_read_close}, q{archive*}},
        {q{int}, q{archive_read_free}, q{archive*}},

        // -- Archive write: new/setup --
        {q{archive*}, q{archive_write_new}},
        {q{int}, q{archive_write_set_bytes_per_block}, q{archive*, int}},
        {q{int}, q{archive_write_get_bytes_per_block}, q{archive*}},
        {q{int}, q{archive_write_set_bytes_in_last_block}, q{archive*, int}},
        {q{int}, q{archive_write_get_bytes_in_last_block}, q{archive*}},
        {q{int}, q{archive_write_set_skip_file}, q{archive*, la_int64_t, la_int64_t}},

        // -- Archive write: filter --
        {q{int}, q{archive_write_add_filter}, q{archive*, int}},
        {q{int}, q{archive_write_add_filter_by_name}, q{archive*, const(char)*}},
        {q{int}, q{archive_write_add_filter_b64encode}, q{archive*}},
        {q{int}, q{archive_write_add_filter_bzip2}, q{archive*}},
        {q{int}, q{archive_write_add_filter_compress}, q{archive*}},
        {q{int}, q{archive_write_add_filter_grzip}, q{archive*}},
        {q{int}, q{archive_write_add_filter_gzip}, q{archive*}},
        {q{int}, q{archive_write_add_filter_lrzip}, q{archive*}},
        {q{int}, q{archive_write_add_filter_lz4}, q{archive*}},
        {q{int}, q{archive_write_add_filter_lzip}, q{archive*}},
        {q{int}, q{archive_write_add_filter_lzma}, q{archive*}},
        {q{int}, q{archive_write_add_filter_lzop}, q{archive*}},
        {q{int}, q{archive_write_add_filter_none}, q{archive*}},
        {q{int}, q{archive_write_add_filter_program}, q{archive*, const(char)*}},
        {q{int}, q{archive_write_add_filter_uuencode}, q{archive*}},
        {q{int}, q{archive_write_add_filter_xz}, q{archive*}},
        {q{int}, q{archive_write_add_filter_zstd}, q{archive*}},

        // -- Archive write: format --
        {q{int}, q{archive_write_set_format}, q{archive*, int}},
        {q{int}, q{archive_write_set_format_by_name}, q{archive*, const(char)*}},
        {q{int}, q{archive_write_set_format_7zip}, q{archive*}},
        {q{int}, q{archive_write_set_format_ar_bsd}, q{archive*}},
        {q{int}, q{archive_write_set_format_ar_svr4}, q{archive*}},
        {q{int}, q{archive_write_set_format_cpio}, q{archive*}},
        {q{int}, q{archive_write_set_format_cpio_bin}, q{archive*}},
        {q{int}, q{archive_write_set_format_cpio_newc}, q{archive*}},
        {q{int}, q{archive_write_set_format_cpio_odc}, q{archive*}},
        {q{int}, q{archive_write_set_format_cpio_pwb}, q{archive*}},
        {q{int}, q{archive_write_set_format_gnutar}, q{archive*}},
        {q{int}, q{archive_write_set_format_iso9660}, q{archive*}},
        {q{int}, q{archive_write_set_format_mtree}, q{archive*}},
        {q{int}, q{archive_write_set_format_mtree_classic}, q{archive*}},
        {q{int}, q{archive_write_set_format_pax}, q{archive*}},
        {q{int}, q{archive_write_set_format_pax_restricted}, q{archive*}},
        {q{int}, q{archive_write_set_format_raw}, q{archive*}},
        {q{int}, q{archive_write_set_format_shar}, q{archive*}},
        {q{int}, q{archive_write_set_format_shar_dump}, q{archive*}},
        {q{int}, q{archive_write_set_format_ustar}, q{archive*}},
        {q{int}, q{archive_write_set_format_v7tar}, q{archive*}},
        {q{int}, q{archive_write_set_format_warc}, q{archive*}},
        {q{int}, q{archive_write_set_format_xar}, q{archive*}},
        {q{int}, q{archive_write_set_format_zip}, q{archive*}},
        {q{int}, q{archive_write_set_format_filter_by_ext}, q{archive*, const(char)*}},
        {q{int}, q{archive_write_set_format_filter_by_ext_def}, q{archive*, const(char)*, const(char)*}},
        {q{int}, q{archive_write_zip_set_compression_deflate}, q{archive*}},
        {q{int}, q{archive_write_zip_set_compression_store}, q{archive*}},

        // -- Archive write: open --
        {q{int}, q{archive_write_open}, q{archive*, void*, archive_open_callback, archive_write_callback, archive_close_callback}},
        {q{int}, q{archive_write_open2}, q{archive*, void*, archive_open_callback, archive_write_callback, archive_close_callback, archive_free_callback}},
        {q{int}, q{archive_write_open_fd}, q{archive*, int}},
        {q{int}, q{archive_write_open_filename}, q{archive*, const(char)*}},
        {q{int}, q{archive_write_open_FILE}, q{archive*, FILE*}},
        {q{int}, q{archive_write_open_memory}, q{archive*, void*, size_t, size_t*}},

        // -- Archive write: data --
        {q{int}, q{archive_write_header}, q{archive*, archive_entry*}},
        {q{la_ssize_t}, q{archive_write_data}, q{archive*, const(void)*, size_t}},
        {q{la_ssize_t}, q{archive_write_data_block}, q{archive*, const(void)*, size_t, la_int64_t}},
        {q{int}, q{archive_write_finish_entry}, q{archive*}},

        // -- Archive write: options --
        {q{int}, q{archive_write_set_format_option}, q{archive*, const(char)*, const(char)*, const(char)*}},
        {q{int}, q{archive_write_set_filter_option}, q{archive*, const(char)*, const(char)*, const(char)*}},
        {q{int}, q{archive_write_set_option}, q{archive*, const(char)*, const(char)*, const(char)*}},
        {q{int}, q{archive_write_set_options}, q{archive*, const(char)*}},

        // -- Archive write: passphrase --
        {q{int}, q{archive_write_set_passphrase}, q{archive*, const(char)*}},
        {q{int}, q{archive_write_set_passphrase_callback}, q{archive*, void*, archive_passphrase_callback}},

        // -- Archive write: close/free --
        {q{int}, q{archive_write_close}, q{archive*}},
        {q{int}, q{archive_write_fail}, q{archive*}},
        {q{int}, q{archive_write_free}, q{archive*}},

        // -- Archive write disk --
        {q{archive*}, q{archive_write_disk_new}},
        {q{int}, q{archive_write_disk_set_skip_file}, q{archive*, la_int64_t, la_int64_t}},
        {q{int}, q{archive_write_disk_set_options}, q{archive*, int}},
        {q{int}, q{archive_write_disk_set_standard_lookup}, q{archive*}},

        // -- Archive read disk --
        {q{archive*}, q{archive_read_disk_new}},
        {q{int}, q{archive_read_disk_set_symlink_logical}, q{archive*}},
        {q{int}, q{archive_read_disk_set_symlink_physical}, q{archive*}},
        {q{int}, q{archive_read_disk_set_symlink_hybrid}, q{archive*}},
        {q{int}, q{archive_read_disk_entry_from_file}, q{archive*, archive_entry*, int, const(void)*}},
        {q{int}, q{archive_read_disk_set_standard_lookup}, q{archive*}},
        {q{int}, q{archive_read_disk_open}, q{archive*, const(char)*}},
        {q{int}, q{archive_read_disk_descend}, q{archive*}},
        {q{int}, q{archive_read_disk_can_descend}, q{archive*}},
        {q{int}, q{archive_read_disk_current_filesystem}, q{archive*}},
        {q{int}, q{archive_read_disk_current_filesystem_is_synthetic}, q{archive*}},
        {q{int}, q{archive_read_disk_current_filesystem_is_remote}, q{archive*}},
        {q{int}, q{archive_read_disk_set_atime_restored}, q{archive*}},
        {q{int}, q{archive_read_disk_set_behavior}, q{archive*, int}},

        // -- Generic accessors --
        {q{int}, q{archive_free}, q{archive*}},
        {q{int}, q{archive_filter_count}, q{archive*}},
        {q{la_int64_t}, q{archive_filter_bytes}, q{archive*, int}},
        {q{int}, q{archive_filter_code}, q{archive*, int}},
        {q{const(char)*}, q{archive_filter_name}, q{archive*, int}},
        {q{int}, q{archive_errno}, q{archive*}},
        {q{const(char)*}, q{archive_error_string}, q{archive*}},
        {q{const(char)*}, q{archive_format_name}, q{archive*}},
        {q{int}, q{archive_format}, q{archive*}},
        {q{void}, q{archive_clear_error}, q{archive*}},
        {q{void}, q{archive_copy_error}, q{archive*, archive*}},
        {q{int}, q{archive_file_count}, q{archive*}},

        // -- Utility --
        {q{int}, q{archive_utility_string_sort}, q{char**}},
    ];
    return ret;
}()));
