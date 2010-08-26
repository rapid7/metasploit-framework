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
#ifndef __LINUX_MSM_ADSP_H
#define __LINUX_MSM_ADSP_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define ADSP_IOCTL_MAGIC 'q'

struct adsp_command_t {
 uint16_t queue;
 uint32_t len;
 uint8_t *data;
};

struct adsp_event_t {
 uint16_t type;
 uint32_t timeout_ms;
 uint16_t msg_id;
 uint16_t flags;
 uint32_t len;
 uint8_t *data;
};

#define ADSP_IOCTL_ENABLE _IOR(ADSP_IOCTL_MAGIC, 1, unsigned)

#define ADSP_IOCTL_DISABLE _IOR(ADSP_IOCTL_MAGIC, 2, unsigned)

#define ADSP_IOCTL_DISABLE_ACK _IOR(ADSP_IOCTL_MAGIC, 3, unsigned)

#define ADSP_IOCTL_WRITE_COMMAND _IOR(ADSP_IOCTL_MAGIC, 4, struct adsp_command_t *)

#define ADSP_IOCTL_GET_EVENT _IOWR(ADSP_IOCTL_MAGIC, 5, struct adsp_event_data_t *)

#define ADSP_IOCTL_SET_CLKRATE _IOR(ADSP_IOCTL_MAGIC, 6, unsigned)

#define ADSP_IOCTL_DISABLE_EVENT_RSP _IOR(ADSP_IOCTL_MAGIC, 10, unsigned)

struct adsp_pmem_info {
 int fd;
 void *vaddr;
};

#define ADSP_IOCTL_REGISTER_PMEM _IOW(ADSP_IOCTL_MAGIC, 13, unsigned)

#define ADSP_IOCTL_UNREGISTER_PMEM _IOW(ADSP_IOCTL_MAGIC, 14, unsigned)

#define ADSP_IOCTL_ABORT_EVENT_READ _IOW(ADSP_IOCTL_MAGIC, 15, unsigned)

#define ADSP_IOCTL_LINK_TASK _IOW(ADSP_IOCTL_MAGIC, 16, unsigned)

#endif

