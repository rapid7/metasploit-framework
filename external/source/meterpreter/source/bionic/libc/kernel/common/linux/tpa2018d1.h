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
#ifndef _LINUX_TPA2018D1_H
#define _LINUX_TPA2018D1_H

#include <linux/ioctl.h>

enum tpa2018d1_mode {
 TPA2018_MODE_OFF,
 TPA2018_MODE_PLAYBACK,
 TPA2018_MODE_RINGTONE,
 TPA2018_MODE_VOICE_CALL,
 TPA2018_NUM_MODES,
};

#define TPA2018_IOCTL_MAGIC 'a'
#define TPA2018_SET_CONFIG _IOW(TPA2018_IOCTL_MAGIC, 1, unsigned)
#define TPA2018_READ_CONFIG _IOR(TPA2018_IOCTL_MAGIC, 2, unsigned)
#define TPA2018_SET_PARAM _IOW(TPA2018_IOCTL_MAGIC, 3, unsigned)
#define TPA2018_SET_MODE _IOW(TPA2018_IOCTL_MAGIC, 4, unsigned)

#endif


