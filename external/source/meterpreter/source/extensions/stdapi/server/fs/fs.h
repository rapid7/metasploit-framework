#ifndef _METERPRETER_SOURCE_EXTENSION_STDAPI_STDAPI_SERVER_FS_FS_H
#define _METERPRETER_SOURCE_EXTENSION_STDAPI_STDAPI_SERVER_FS_FS_H

LPSTR fs_expand_path(LPCSTR regular);

/*
 * File system interaction
 */
DWORD request_fs_ls(Remote *remote, Packet *packet);
DWORD request_fs_getwd(Remote *remote, Packet *packet);
DWORD request_fs_chdir(Remote *remote, Packet *packet);
DWORD request_fs_mkdir(Remote *remote, Packet *packet);
DWORD request_fs_delete_dir(Remote *remote, Packet *packet);
DWORD request_fs_delete_file(Remote *remote, Packet *packet);
DWORD request_fs_separator(Remote *remote, Packet *packet);
DWORD request_fs_stat(Remote *remote, Packet *packet);
DWORD request_fs_file_expand_path(Remote *remote, Packet *packet);
DWORD request_fs_search( Remote * remote, Packet * packet );
DWORD request_fs_md5(Remote *remote, Packet *packet);
DWORD request_fs_sha1(Remote *remote, Packet *packet);

/*
 * Channel allocation
 */
DWORD request_fs_file_channel_open(Remote *remote, Packet *packet);



/*
 * Stat structures on Windows and various Unixes are all slightly different.
 * Use this as a means of standardization so the client has some hope of
 * understanding what the stat'd file really is.
 */
struct meterp_stat {
    unsigned int   st_dev;
    unsigned short st_ino;
    unsigned short st_mode;
    unsigned short st_nlink;
    unsigned short st_uid;
    unsigned short st_gid;
    unsigned short pad;
    unsigned int   st_rdev;
    unsigned int   st_size;
    /*
     * These are always 64-bits on Windows and usually 32-bits on Linux.  Force
     * them to be the same size everywhere.
     */
    unsigned long long st_atime;
    unsigned long long st_mtime;
    unsigned long long st_ctime;
};

int fs_stat(LPCSTR filename, struct meterp_stat *buf);


#endif
