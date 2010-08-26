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
#ifndef _LINUX_USBDEVICE_FS_H
#define _LINUX_USBDEVICE_FS_H

#include <linux/types.h>

#define USBDEVICE_SUPER_MAGIC 0x9fa2

struct usbdevfs_ctrltransfer {
 __u8 bRequestType;
 __u8 bRequest;
 __u16 wValue;
 __u16 wIndex;
 __u16 wLength;
 __u32 timeout;
 void __user *data;
};

struct usbdevfs_bulktransfer {
 unsigned int ep;
 unsigned int len;
 unsigned int timeout;
 void __user *data;
};

struct usbdevfs_setinterface {
 unsigned int interface;
 unsigned int altsetting;
};

struct usbdevfs_disconnectsignal {
 unsigned int signr;
 void __user *context;
};

#define USBDEVFS_MAXDRIVERNAME 255

struct usbdevfs_getdriver {
 unsigned int interface;
 char driver[USBDEVFS_MAXDRIVERNAME + 1];
};

struct usbdevfs_connectinfo {
 unsigned int devnum;
 unsigned char slow;
};

#define USBDEVFS_URB_SHORT_NOT_OK 1
#define USBDEVFS_URB_ISO_ASAP 2

#define USBDEVFS_URB_TYPE_ISO 0
#define USBDEVFS_URB_TYPE_INTERRUPT 1
#define USBDEVFS_URB_TYPE_CONTROL 2
#define USBDEVFS_URB_TYPE_BULK 3

struct usbdevfs_iso_packet_desc {
 unsigned int length;
 unsigned int actual_length;
 unsigned int status;
};

struct usbdevfs_urb {
 unsigned char type;
 unsigned char endpoint;
 int status;
 unsigned int flags;
 void __user *buffer;
 int buffer_length;
 int actual_length;
 int start_frame;
 int number_of_packets;
 int error_count;
 unsigned int signr;
 void *usercontext;
 struct usbdevfs_iso_packet_desc iso_frame_desc[0];
};

struct usbdevfs_ioctl {
 int ifno;
 int ioctl_code;
 void __user *data;
};

struct usbdevfs_hub_portinfo {
 char nports;
 char port [127];
};

#define USBDEVFS_CONTROL _IOWR('U', 0, struct usbdevfs_ctrltransfer)
#define USBDEVFS_BULK _IOWR('U', 2, struct usbdevfs_bulktransfer)
#define USBDEVFS_RESETEP _IOR('U', 3, unsigned int)
#define USBDEVFS_SETINTERFACE _IOR('U', 4, struct usbdevfs_setinterface)
#define USBDEVFS_SETCONFIGURATION _IOR('U', 5, unsigned int)
#define USBDEVFS_GETDRIVER _IOW('U', 8, struct usbdevfs_getdriver)
#define USBDEVFS_SUBMITURB _IOR('U', 10, struct usbdevfs_urb)
#define USBDEVFS_SUBMITURB32 _IOR('U', 10, struct usbdevfs_urb32)
#define USBDEVFS_DISCARDURB _IO('U', 11)
#define USBDEVFS_REAPURB _IOW('U', 12, void *)
#define USBDEVFS_REAPURB32 _IOW('U', 12, u32)
#define USBDEVFS_REAPURBNDELAY _IOW('U', 13, void *)
#define USBDEVFS_REAPURBNDELAY32 _IOW('U', 13, u32)
#define USBDEVFS_DISCSIGNAL _IOR('U', 14, struct usbdevfs_disconnectsignal)
#define USBDEVFS_CLAIMINTERFACE _IOR('U', 15, unsigned int)
#define USBDEVFS_RELEASEINTERFACE _IOR('U', 16, unsigned int)
#define USBDEVFS_CONNECTINFO _IOW('U', 17, struct usbdevfs_connectinfo)
#define USBDEVFS_IOCTL _IOWR('U', 18, struct usbdevfs_ioctl)
#define USBDEVFS_IOCTL32 _IOWR('U', 18, struct usbdevfs_ioctl32)
#define USBDEVFS_HUB_PORTINFO _IOR('U', 19, struct usbdevfs_hub_portinfo)
#define USBDEVFS_RESET _IO('U', 20)
#define USBDEVFS_CLEAR_HALT _IOR('U', 21, unsigned int)
#define USBDEVFS_DISCONNECT _IO('U', 22)
#define USBDEVFS_CONNECT _IO('U', 23)
#endif
