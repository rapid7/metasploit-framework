#import <sys/snapshot.h>
#import <sys/mount.h>

int list_snapshots(const char *vol);
char *find_system_snapshot(void);
int do_rename(const char *vol, const char *snap, const char *nw);
char *copyBootHash(void);
int snapshot_check(const char *vol, const char *name);
int mountSnapshot(const char *vol, const char *name, const char *dir);

struct hfs_mount_args {
    char    *fspec;            /* block special device to mount */
    uid_t    hfs_uid;        /* uid that owns hfs files (standard HFS only) */
    gid_t    hfs_gid;        /* gid that owns hfs files (standard HFS only) */
    mode_t    hfs_mask;        /* mask to be applied for hfs perms  (standard HFS only) */
    u_int32_t hfs_encoding;    /* encoding for this volume (standard HFS only) */
    struct    timezone hfs_timezone;    /* user time zone info (standard HFS only) */
    int        flags;            /* mounting flags, see below */
    int     journal_tbuffer_size;   /* size in bytes of the journal transaction buffer */
    int        journal_flags;          /* flags to pass to journal_open/create */
    int        journal_disable;        /* don't use journaling (potentially dangerous) */
};
