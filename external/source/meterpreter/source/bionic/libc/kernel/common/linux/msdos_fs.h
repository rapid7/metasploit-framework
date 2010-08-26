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
#ifndef _LINUX_MSDOS_FS_H
#define _LINUX_MSDOS_FS_H

#include <linux/magic.h>

#include <asm/byteorder.h>

#define SECTOR_SIZE 512  
#define SECTOR_BITS 9  
#define MSDOS_DPB (MSDOS_DPS)  
#define MSDOS_DPB_BITS 4  
#define MSDOS_DPS (SECTOR_SIZE / sizeof(struct msdos_dir_entry))
#define MSDOS_DPS_BITS 4  
#define CF_LE_W(v) le16_to_cpu(v)
#define CF_LE_L(v) le32_to_cpu(v)
#define CT_LE_W(v) cpu_to_le16(v)
#define CT_LE_L(v) cpu_to_le32(v)

#define MSDOS_ROOT_INO 1  
#define MSDOS_DIR_BITS 5  

#define FAT_MAX_DIR_ENTRIES (65536)
#define FAT_MAX_DIR_SIZE (FAT_MAX_DIR_ENTRIES << MSDOS_DIR_BITS)

#define ATTR_NONE 0  
#define ATTR_RO 1  
#define ATTR_HIDDEN 2  
#define ATTR_SYS 4  
#define ATTR_VOLUME 8  
#define ATTR_DIR 16  
#define ATTR_ARCH 32  

#define ATTR_UNUSED (ATTR_VOLUME | ATTR_ARCH | ATTR_SYS | ATTR_HIDDEN)

#define ATTR_EXT (ATTR_RO | ATTR_HIDDEN | ATTR_SYS | ATTR_VOLUME)

#define CASE_LOWER_BASE 8  
#define CASE_LOWER_EXT 16  

#define DELETED_FLAG 0xe5  
#define IS_FREE(n) (!*(n) || *(n) == DELETED_FLAG)

#define MSDOS_VALID_MODE (S_IFREG | S_IFDIR | S_IRWXU | S_IRWXG | S_IRWXO)

#define MSDOS_MKMODE(a, m) (m & (a & ATTR_RO ? S_IRUGO|S_IXUGO : S_IRWXUGO))

#define MSDOS_NAME 11  
#define MSDOS_LONGNAME 256  
#define MSDOS_SLOTS 21  
#define MSDOS_DOT ".          "  
#define MSDOS_DOTDOT "..         "  

#define FAT_VALID_MEDIA(x) ((0xF8 <= (x) && (x) <= 0xFF) || (x) == 0xF0)
#define FAT_FIRST_ENT(s, x) ((MSDOS_SB(s)->fat_bits == 32 ? 0x0FFFFF00 :   MSDOS_SB(s)->fat_bits == 16 ? 0xFF00 : 0xF00) | (x))

#define FAT_START_ENT 2

#define MAX_FAT12 0xFF4
#define MAX_FAT16 0xFFF4
#define MAX_FAT32 0x0FFFFFF6
#define MAX_FAT(s) (MSDOS_SB(s)->fat_bits == 32 ? MAX_FAT32 :   MSDOS_SB(s)->fat_bits == 16 ? MAX_FAT16 : MAX_FAT12)

#define BAD_FAT12 0xFF7
#define BAD_FAT16 0xFFF7
#define BAD_FAT32 0x0FFFFFF7

#define EOF_FAT12 0xFFF
#define EOF_FAT16 0xFFFF
#define EOF_FAT32 0x0FFFFFFF

#define FAT_ENT_FREE (0)
#define FAT_ENT_BAD (BAD_FAT32)
#define FAT_ENT_EOF (EOF_FAT32)

#define FAT_FSINFO_SIG1 0x41615252
#define FAT_FSINFO_SIG2 0x61417272
#define IS_FSINFO(x) (le32_to_cpu((x)->signature1) == FAT_FSINFO_SIG1   && le32_to_cpu((x)->signature2) == FAT_FSINFO_SIG2)

#define VFAT_IOCTL_READDIR_BOTH _IOR('r', 1, struct dirent [2])
#define VFAT_IOCTL_READDIR_SHORT _IOR('r', 2, struct dirent [2])

#define FAT_IOCTL_GET_ATTRIBUTES _IOR('r', 0x10, __u32)
#define FAT_IOCTL_SET_ATTRIBUTES _IOW('r', 0x11, __u32)
#define VFAT_IOCTL_GET_VOLUME_ID _IOR('r', 0x12, __u32)

#define VFAT_SFN_DISPLAY_LOWER 0x0001  
#define VFAT_SFN_DISPLAY_WIN95 0x0002  
#define VFAT_SFN_DISPLAY_WINNT 0x0004  
#define VFAT_SFN_CREATE_WIN95 0x0100  
#define VFAT_SFN_CREATE_WINNT 0x0200  

struct fat_boot_sector {
 __u8 ignored[3];
 __u8 system_id[8];
 __u8 sector_size[2];
 __u8 sec_per_clus;
 __le16 reserved;
 __u8 fats;
 __u8 dir_entries[2];
 __u8 sectors[2];
 __u8 media;
 __le16 fat_length;
 __le16 secs_track;
 __le16 heads;
 __le32 hidden;
 __le32 total_sect;

 __le32 fat32_length;
 __le16 flags;
 __u8 version[2];
 __le32 root_cluster;
 __le16 info_sector;
 __le16 backup_boot;
 __le16 reserved2[6];
};

struct fat_boot_fsinfo {
 __le32 signature1;
 __le32 reserved1[120];
 __le32 signature2;
 __le32 free_clusters;
 __le32 next_cluster;
 __le32 reserved2[4];
};

struct fat_boot_bsx {
 __u8 drive;
 __u8 reserved1;
 __u8 signature;
 __u8 vol_id[4];
 __u8 vol_label[11];
 __u8 type[8];
};
#define FAT16_BSX_OFFSET 36  
#define FAT32_BSX_OFFSET 64  

struct msdos_dir_entry {
 __u8 name[MSDOS_NAME];
 __u8 attr;
 __u8 lcase;
 __u8 ctime_cs;
 __le16 ctime;
 __le16 cdate;
 __le16 adate;
 __le16 starthi;
 __le16 time,date,start;
 __le32 size;
};

struct msdos_dir_slot {
 __u8 id;
 __u8 name0_4[10];
 __u8 attr;
 __u8 reserved;
 __u8 alias_checksum;
 __u8 name5_10[12];
 __le16 start;
 __u8 name11_12[4];
};

struct fat_slot_info {
 loff_t i_pos;
 loff_t slot_off;
 int nr_slots;
 struct msdos_dir_entry *de;
 struct buffer_head *bh;
};

#endif
