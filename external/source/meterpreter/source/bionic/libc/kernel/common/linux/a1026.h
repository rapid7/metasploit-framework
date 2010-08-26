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
#ifndef __LINUX_A1026_H
#define __LINUX_A1026_H

#include <linux/ioctl.h>

#define A1026_MAX_FW_SIZE (32*1024)
struct a1026img {
 unsigned char *buf;
 unsigned img_size;
};

enum A1026_PathID {
 A1026_PATH_SUSPEND,
 A1026_PATH_INCALL_RECEIVER,
 A1026_PATH_INCALL_HEADSET,
 A1026_PATH_INCALL_SPEAKER,
 A1026_PATH_INCALL_BT,
 A1026_PATH_VR_NO_NS_RECEIVER,
 A1026_PATH_VR_NO_NS_HEADSET,
 A1026_PATH_VR_NO_NS_SPEAKER,
 A1026_PATH_VR_NO_NS_BT,
 A1026_PATH_VR_NS_RECEIVER,
 A1026_PATH_VR_NS_HEADSET,
 A1026_PATH_VR_NS_SPEAKER,
 A1026_PATH_VR_NS_BT,
 A1026_PATH_RECORD_RECEIVER,
 A1026_PATH_RECORD_HEADSET,
 A1026_PATH_RECORD_SPEAKER,
 A1026_PATH_RECORD_BT,
 A1026_PATH_CAMCORDER,
 A1026_PATH_INCALL_TTY
};

enum A1026_NS_states {
 A1026_NS_STATE_AUTO,
 A1026_NS_STATE_OFF,
 A1026_NS_STATE_CT,
 A1026_NS_STATE_FT,
 A1026_NS_NUM_STATES
};

#define A1026_IOCTL_MAGIC 'u'

#define A1026_BOOTUP_INIT _IOW(A1026_IOCTL_MAGIC, 0x01, struct a1026img *)
#define A1026_SET_CONFIG _IOW(A1026_IOCTL_MAGIC, 0x02, enum A1026_PathID)
#define A1026_SET_NS_STATE _IOW(A1026_IOCTL_MAGIC, 0x03, enum A1026_NS_states)

#define A1026_SET_MIC_ONOFF _IOW(A1026_IOCTL_MAGIC, 0x50, unsigned)
#define A1026_SET_MICSEL_ONOFF _IOW(A1026_IOCTL_MAGIC, 0x51, unsigned)
#define A1026_READ_DATA _IOR(A1026_IOCTL_MAGIC, 0x52, unsigned)
#define A1026_WRITE_MSG _IOW(A1026_IOCTL_MAGIC, 0x53, unsigned)
#define A1026_SYNC_CMD _IO(A1026_IOCTL_MAGIC, 0x54)
#define A1026_SET_CMD_FILE _IOW(A1026_IOCTL_MAGIC, 0x55, unsigned)

#endif

