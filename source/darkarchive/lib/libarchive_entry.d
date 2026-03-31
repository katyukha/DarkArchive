/// D bindings for libarchive's archive_entry.h, using bindbc-common codegen.
module darkarchive.lib.libarchive_entry;

private import bindbc.common.codegen : joinFnBinds, FnBind;
public import darkarchive.lib.types;
import core.stdc.config : c_long;

enum staticBinding = () {
    version(BindBC_Static)          return true;
    else version(DarkArchiveStatic) return true;
    else return false;
}();

mixin(joinFnBinds!staticBinding((){
    FnBind[] ret = [

        // -- Object lifecycle --
        {q{archive_entry*}, q{archive_entry_clear}, q{archive_entry*}},
        {q{archive_entry*}, q{archive_entry_clone}, q{archive_entry*}},
        {q{void}, q{archive_entry_free}, q{archive_entry*}},
        {q{archive_entry*}, q{archive_entry_new}},
        {q{archive_entry*}, q{archive_entry_new2}, q{archive*}},

        // -- Getters: time --
        {q{time_t}, q{archive_entry_atime}, q{archive_entry*}},
        {q{c_long}, q{archive_entry_atime_nsec}, q{archive_entry*}},
        {q{int}, q{archive_entry_atime_is_set}, q{archive_entry*}},
        {q{time_t}, q{archive_entry_birthtime}, q{archive_entry*}},
        {q{c_long}, q{archive_entry_birthtime_nsec}, q{archive_entry*}},
        {q{int}, q{archive_entry_birthtime_is_set}, q{archive_entry*}},
        {q{time_t}, q{archive_entry_ctime}, q{archive_entry*}},
        {q{c_long}, q{archive_entry_ctime_nsec}, q{archive_entry*}},
        {q{int}, q{archive_entry_ctime_is_set}, q{archive_entry*}},
        {q{time_t}, q{archive_entry_mtime}, q{archive_entry*}},
        {q{c_long}, q{archive_entry_mtime_nsec}, q{archive_entry*}},
        {q{int}, q{archive_entry_mtime_is_set}, q{archive_entry*}},

        // -- Getters: file type/mode --
        {q{uint}, q{archive_entry_filetype}, q{archive_entry*}},
        {q{int}, q{archive_entry_filetype_is_set}, q{archive_entry*}},
        {q{uint}, q{archive_entry_mode}, q{archive_entry*}},
        {q{uint}, q{archive_entry_perm}, q{archive_entry*}},
        {q{int}, q{archive_entry_perm_is_set}, q{archive_entry*}},

        // -- Getters: identity --
        {q{la_int64_t}, q{archive_entry_uid}, q{archive_entry*}},
        {q{int}, q{archive_entry_uid_is_set}, q{archive_entry*}},
        {q{la_int64_t}, q{archive_entry_gid}, q{archive_entry*}},
        {q{int}, q{archive_entry_gid_is_set}, q{archive_entry*}},
        {q{const(char)*}, q{archive_entry_uname}, q{archive_entry*}},
        {q{const(char)*}, q{archive_entry_uname_utf8}, q{archive_entry*}},
        {q{const(char)*}, q{archive_entry_gname}, q{archive_entry*}},
        {q{const(char)*}, q{archive_entry_gname_utf8}, q{archive_entry*}},

        // -- Getters: path --
        {q{const(char)*}, q{archive_entry_pathname}, q{archive_entry*}},
        {q{const(char)*}, q{archive_entry_pathname_utf8}, q{archive_entry*}},
        {q{const(char)*}, q{archive_entry_sourcepath}, q{archive_entry*}},

        // -- Getters: size --
        {q{la_int64_t}, q{archive_entry_size}, q{archive_entry*}},
        {q{int}, q{archive_entry_size_is_set}, q{archive_entry*}},

        // -- Getters: link --
        {q{const(char)*}, q{archive_entry_hardlink}, q{archive_entry*}},
        {q{const(char)*}, q{archive_entry_hardlink_utf8}, q{archive_entry*}},
        {q{int}, q{archive_entry_hardlink_is_set}, q{archive_entry*}},
        {q{const(char)*}, q{archive_entry_symlink}, q{archive_entry*}},
        {q{const(char)*}, q{archive_entry_symlink_utf8}, q{archive_entry*}},
        {q{int}, q{archive_entry_symlink_type}, q{archive_entry*}},

        // -- Getters: misc --
        {q{uint}, q{archive_entry_nlink}, q{archive_entry*}},
        {q{la_int64_t}, q{archive_entry_ino64}, q{archive_entry*}},
        {q{la_int64_t}, q{archive_entry_ino}, q{archive_entry*}},
        {q{int}, q{archive_entry_ino_is_set}, q{archive_entry*}},
        {q{const(char)*}, q{archive_entry_fflags_text}, q{archive_entry*}},
        {q{const(char)*}, q{archive_entry_strmode}, q{archive_entry*}},
        {q{int}, q{archive_entry_is_data_encrypted}, q{archive_entry*}},
        {q{int}, q{archive_entry_is_metadata_encrypted}, q{archive_entry*}},
        {q{int}, q{archive_entry_is_encrypted}, q{archive_entry*}},
        {q{const(ubyte)*}, q{archive_entry_digest}, q{archive_entry*, int}},

        // -- Getters: fflags --
        {q{void}, q{archive_entry_fflags}, q{archive_entry*, ulong*, ulong*}},

        // -- Getters: dev --
        {q{int}, q{archive_entry_dev_is_set}, q{archive_entry*}},
        {q{int}, q{archive_entry_rdev_is_set}, q{archive_entry*}},

        // -- Setters: time --
        {q{void}, q{archive_entry_set_atime}, q{archive_entry*, time_t, c_long}},
        {q{void}, q{archive_entry_unset_atime}, q{archive_entry*}},
        {q{void}, q{archive_entry_set_birthtime}, q{archive_entry*, time_t, c_long}},
        {q{void}, q{archive_entry_unset_birthtime}, q{archive_entry*}},
        {q{void}, q{archive_entry_set_ctime}, q{archive_entry*, time_t, c_long}},
        {q{void}, q{archive_entry_unset_ctime}, q{archive_entry*}},
        {q{void}, q{archive_entry_set_mtime}, q{archive_entry*, time_t, c_long}},
        {q{void}, q{archive_entry_unset_mtime}, q{archive_entry*}},

        // -- Setters: file type/mode --
        {q{void}, q{archive_entry_set_filetype}, q{archive_entry*, uint}},
        {q{void}, q{archive_entry_set_mode}, q{archive_entry*, uint}},
        {q{void}, q{archive_entry_set_perm}, q{archive_entry*, uint}},

        // -- Setters: identity --
        {q{void}, q{archive_entry_set_uid}, q{archive_entry*, la_int64_t}},
        {q{void}, q{archive_entry_set_gid}, q{archive_entry*, la_int64_t}},
        {q{void}, q{archive_entry_set_uname}, q{archive_entry*, const(char)*}},
        {q{void}, q{archive_entry_set_uname_utf8}, q{archive_entry*, const(char)*}},
        {q{void}, q{archive_entry_copy_uname}, q{archive_entry*, const(char)*}},
        {q{int}, q{archive_entry_update_uname_utf8}, q{archive_entry*, const(char)*}},
        {q{void}, q{archive_entry_set_gname}, q{archive_entry*, const(char)*}},
        {q{void}, q{archive_entry_set_gname_utf8}, q{archive_entry*, const(char)*}},
        {q{void}, q{archive_entry_copy_gname}, q{archive_entry*, const(char)*}},
        {q{int}, q{archive_entry_update_gname_utf8}, q{archive_entry*, const(char)*}},

        // -- Setters: path --
        {q{void}, q{archive_entry_set_pathname}, q{archive_entry*, const(char)*}},
        {q{void}, q{archive_entry_set_pathname_utf8}, q{archive_entry*, const(char)*}},
        {q{void}, q{archive_entry_copy_pathname}, q{archive_entry*, const(char)*}},
        {q{int}, q{archive_entry_update_pathname_utf8}, q{archive_entry*, const(char)*}},
        {q{void}, q{archive_entry_copy_sourcepath}, q{archive_entry*, const(char)*}},

        // -- Setters: size --
        {q{void}, q{archive_entry_set_size}, q{archive_entry*, la_int64_t}},
        {q{void}, q{archive_entry_unset_size}, q{archive_entry*}},

        // -- Setters: link --
        {q{void}, q{archive_entry_set_hardlink}, q{archive_entry*, const(char)*}},
        {q{void}, q{archive_entry_set_hardlink_utf8}, q{archive_entry*, const(char)*}},
        {q{void}, q{archive_entry_copy_hardlink}, q{archive_entry*, const(char)*}},
        {q{int}, q{archive_entry_update_hardlink_utf8}, q{archive_entry*, const(char)*}},
        {q{void}, q{archive_entry_set_symlink}, q{archive_entry*, const(char)*}},
        {q{void}, q{archive_entry_set_symlink_type}, q{archive_entry*, int}},
        {q{void}, q{archive_entry_set_symlink_utf8}, q{archive_entry*, const(char)*}},
        {q{void}, q{archive_entry_copy_symlink}, q{archive_entry*, const(char)*}},
        {q{int}, q{archive_entry_update_symlink_utf8}, q{archive_entry*, const(char)*}},
        {q{void}, q{archive_entry_set_link}, q{archive_entry*, const(char)*}},
        {q{void}, q{archive_entry_set_link_utf8}, q{archive_entry*, const(char)*}},
        {q{void}, q{archive_entry_copy_link}, q{archive_entry*, const(char)*}},
        {q{int}, q{archive_entry_update_link_utf8}, q{archive_entry*, const(char)*}},
        {q{void}, q{archive_entry_set_link_to_hardlink}, q{archive_entry*}},
        {q{void}, q{archive_entry_set_link_to_symlink}, q{archive_entry*}},

        // -- Setters: misc --
        {q{void}, q{archive_entry_set_nlink}, q{archive_entry*, uint}},
        {q{void}, q{archive_entry_set_ino}, q{archive_entry*, la_int64_t}},
        {q{void}, q{archive_entry_set_ino64}, q{archive_entry*, la_int64_t}},
        {q{void}, q{archive_entry_set_fflags}, q{archive_entry*, ulong, ulong}},
        {q{const(char)*}, q{archive_entry_copy_fflags_text}, q{archive_entry*, const(char)*}},
        {q{void}, q{archive_entry_set_is_data_encrypted}, q{archive_entry*, byte}},
        {q{void}, q{archive_entry_set_is_metadata_encrypted}, q{archive_entry*, byte}},

        // -- Xattr --
        {q{void}, q{archive_entry_xattr_clear}, q{archive_entry*}},
        {q{void}, q{archive_entry_xattr_add_entry}, q{archive_entry*, const(char)*, const(void)*, size_t}},
        {q{int}, q{archive_entry_xattr_count}, q{archive_entry*}},
        {q{int}, q{archive_entry_xattr_reset}, q{archive_entry*}},
        {q{int}, q{archive_entry_xattr_next}, q{archive_entry*, const(char)**, const(void)**, size_t*}},

        // -- Sparse --
        {q{void}, q{archive_entry_sparse_clear}, q{archive_entry*}},
        {q{void}, q{archive_entry_sparse_add_entry}, q{archive_entry*, la_int64_t, la_int64_t}},
        {q{int}, q{archive_entry_sparse_count}, q{archive_entry*}},
        {q{int}, q{archive_entry_sparse_reset}, q{archive_entry*}},
        {q{int}, q{archive_entry_sparse_next}, q{archive_entry*, la_int64_t*, la_int64_t*}},

        // -- Link resolver --
        {q{archive_entry_linkresolver*}, q{archive_entry_linkresolver_new}},
        {q{void}, q{archive_entry_linkresolver_set_strategy}, q{archive_entry_linkresolver*, int}},
        {q{void}, q{archive_entry_linkresolver_free}, q{archive_entry_linkresolver*}},
        {q{void}, q{archive_entry_linkify}, q{archive_entry_linkresolver*, archive_entry**, archive_entry**}},

        // -- ACL --
        {q{void}, q{archive_entry_acl_clear}, q{archive_entry*}},
        {q{int}, q{archive_entry_acl_add_entry}, q{archive_entry*, int, int, int, int, const(char)*}},
        {q{int}, q{archive_entry_acl_reset}, q{archive_entry*, int}},
        {q{int}, q{archive_entry_acl_next}, q{archive_entry*, int, int*, int*, int*, int*, const(char)**}},
        {q{int}, q{archive_entry_acl_types}, q{archive_entry*}},
        {q{int}, q{archive_entry_acl_count}, q{archive_entry*, int}},
        {q{const(char)*}, q{archive_entry_acl_text}, q{archive_entry*, int}},
        {q{int}, q{archive_entry_acl_from_text}, q{archive_entry*, const(char)*, int}},
        {q{archive_acl*}, q{archive_entry_acl}, q{archive_entry*}},

        // -- Mac metadata --
        {q{const(void)*}, q{archive_entry_mac_metadata}, q{archive_entry*, size_t*}},
        {q{void}, q{archive_entry_copy_mac_metadata}, q{archive_entry*, const(void)*, size_t}},
    ];
    return ret;
}()));
