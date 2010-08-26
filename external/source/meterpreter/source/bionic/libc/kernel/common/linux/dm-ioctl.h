/****************************************************************************
 ****************************************************************************
 ***
 ***   This header was automatically generated from a Linux kernel header
 ***   of the same name, to make information necessary for userspace to
 ***   call into the kernel available to libc.  It contains only constants,
 ***   structures, and macros generated from the original header, and thus,
 ***   contains no copyrightable information.
 ***
 ****************************************************************************
 ****************************************************************************/
#ifndef _LINUX_DM_IOCTL_V4_H
#define _LINUX_DM_IOCTL_V4_H

#include <linux/types.h>

#define DM_DIR "mapper"  
#define DM_MAX_TYPE_NAME 16
#define DM_NAME_LEN 128
#define DM_UUID_LEN 129

struct dm_ioctl {

 uint32_t version[3];
 uint32_t data_size;

 uint32_t data_start;

 uint32_t target_count;
 int32_t open_count;
 uint32_t flags;
 uint32_t event_nr;
 uint32_t padding;

 uint64_t dev;

 char name[DM_NAME_LEN];
 char uuid[DM_UUID_LEN];
 char data[7];
};

struct dm_target_spec {
 uint64_t sector_start;
 uint64_t length;
 int32_t status;

 uint32_t next;

 char target_type[DM_MAX_TYPE_NAME];

};

struct dm_target_deps {
 uint32_t count;
 uint32_t padding;
 uint64_t dev[0];
};

struct dm_name_list {
 uint64_t dev;
 uint32_t next;
 char name[0];
};

struct dm_target_versions {
 uint32_t next;
 uint32_t version[3];

 char name[0];
};

struct dm_target_msg {
 uint64_t sector;

 char message[0];
};

enum {

 DM_VERSION_CMD = 0,
 DM_REMOVE_ALL_CMD,
 DM_LIST_DEVICES_CMD,

 DM_DEV_CREATE_CMD,
 DM_DEV_REMOVE_CMD,
 DM_DEV_RENAME_CMD,
 DM_DEV_SUSPEND_CMD,
 DM_DEV_STATUS_CMD,
 DM_DEV_WAIT_CMD,

 DM_TABLE_LOAD_CMD,
 DM_TABLE_CLEAR_CMD,
 DM_TABLE_DEPS_CMD,
 DM_TABLE_STATUS_CMD,

 DM_LIST_VERSIONS_CMD,
 DM_TARGET_MSG_CMD,
 DM_DEV_SET_GEOMETRY_CMD
};

#define DM_IOCTL 0xfd

#define DM_VERSION _IOWR(DM_IOCTL, DM_VERSION_CMD, struct dm_ioctl)
#define DM_REMOVE_ALL _IOWR(DM_IOCTL, DM_REMOVE_ALL_CMD, struct dm_ioctl)
#define DM_LIST_DEVICES _IOWR(DM_IOCTL, DM_LIST_DEVICES_CMD, struct dm_ioctl)

#define DM_DEV_CREATE _IOWR(DM_IOCTL, DM_DEV_CREATE_CMD, struct dm_ioctl)
#define DM_DEV_REMOVE _IOWR(DM_IOCTL, DM_DEV_REMOVE_CMD, struct dm_ioctl)
#define DM_DEV_RENAME _IOWR(DM_IOCTL, DM_DEV_RENAME_CMD, struct dm_ioctl)
#define DM_DEV_SUSPEND _IOWR(DM_IOCTL, DM_DEV_SUSPEND_CMD, struct dm_ioctl)
#define DM_DEV_STATUS _IOWR(DM_IOCTL, DM_DEV_STATUS_CMD, struct dm_ioctl)
#define DM_DEV_WAIT _IOWR(DM_IOCTL, DM_DEV_WAIT_CMD, struct dm_ioctl)

#define DM_TABLE_LOAD _IOWR(DM_IOCTL, DM_TABLE_LOAD_CMD, struct dm_ioctl)
#define DM_TABLE_CLEAR _IOWR(DM_IOCTL, DM_TABLE_CLEAR_CMD, struct dm_ioctl)
#define DM_TABLE_DEPS _IOWR(DM_IOCTL, DM_TABLE_DEPS_CMD, struct dm_ioctl)
#define DM_TABLE_STATUS _IOWR(DM_IOCTL, DM_TABLE_STATUS_CMD, struct dm_ioctl)

#define DM_LIST_VERSIONS _IOWR(DM_IOCTL, DM_LIST_VERSIONS_CMD, struct dm_ioctl)

#define DM_TARGET_MSG _IOWR(DM_IOCTL, DM_TARGET_MSG_CMD, struct dm_ioctl)
#define DM_DEV_SET_GEOMETRY _IOWR(DM_IOCTL, DM_DEV_SET_GEOMETRY_CMD, struct dm_ioctl)

#define DM_VERSION_MAJOR 4
#define DM_VERSION_MINOR 14
#define DM_VERSION_PATCHLEVEL 0
#define DM_VERSION_EXTRA "-ioctl (2008-04-23)"

#define DM_READONLY_FLAG (1 << 0)  
#define DM_SUSPEND_FLAG (1 << 1)  
#define DM_PERSISTENT_DEV_FLAG (1 << 3)  

#define DM_STATUS_TABLE_FLAG (1 << 4)  

#define DM_ACTIVE_PRESENT_FLAG (1 << 5)  
#define DM_INACTIVE_PRESENT_FLAG (1 << 6)  

#define DM_BUFFER_FULL_FLAG (1 << 8)  

#define DM_SKIP_BDGET_FLAG (1 << 9)  

#define DM_SKIP_LOCKFS_FLAG (1 << 10)  

#define DM_NOFLUSH_FLAG (1 << 11)  

#endif
