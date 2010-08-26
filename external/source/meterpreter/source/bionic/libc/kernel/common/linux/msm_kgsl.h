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
#ifndef _MSM_KGSL_H
#define _MSM_KGSL_H

#define KGSL_CONTEXT_SAVE_GMEM 1
#define KGSL_CONTEXT_NO_GMEM_ALLOC 2

#define KGSL_FLAGS_NORMALMODE 0x00000000
#define KGSL_FLAGS_SAFEMODE 0x00000001
#define KGSL_FLAGS_INITIALIZED0 0x00000002
#define KGSL_FLAGS_INITIALIZED 0x00000004
#define KGSL_FLAGS_STARTED 0x00000008
#define KGSL_FLAGS_ACTIVE 0x00000010
#define KGSL_FLAGS_RESERVED0 0x00000020
#define KGSL_FLAGS_RESERVED1 0x00000040
#define KGSL_FLAGS_RESERVED2 0x00000080

enum kgsl_deviceid {
 KGSL_DEVICE_ANY = 0x00000000,
 KGSL_DEVICE_YAMATO = 0x00000001,
 KGSL_DEVICE_G12 = 0x00000002,
 KGSL_DEVICE_MAX = 0x00000002
};

struct kgsl_devinfo {

 unsigned int device_id;

 unsigned int chip_id;
 unsigned int mmu_enabled;
 unsigned int gmem_gpubaseaddr;

 unsigned int gmem_hostbaseaddr;
 unsigned int gmem_sizebytes;
};

struct kgsl_devmemstore {
 volatile unsigned int soptimestamp;
 unsigned int sbz;
 volatile unsigned int eoptimestamp;
 unsigned int sbz2;
 volatile unsigned int ts_cmp_enable;
 unsigned int sbz3;
 volatile unsigned int ref_wait_ts;
 unsigned int sbz4;
};

#define KGSL_DEVICE_MEMSTORE_OFFSET(field)   offsetof(struct kgsl_devmemstore, field)

enum kgsl_timestamp_type {
 KGSL_TIMESTAMP_CONSUMED = 0x00000001,
 KGSL_TIMESTAMP_RETIRED = 0x00000002,
 KGSL_TIMESTAMP_MAX = 0x00000002,
};

enum kgsl_property_type {
 KGSL_PROP_DEVICE_INFO = 0x00000001,
 KGSL_PROP_DEVICE_SHADOW = 0x00000002,
 KGSL_PROP_DEVICE_POWER = 0x00000003,
 KGSL_PROP_SHMEM = 0x00000004,
 KGSL_PROP_SHMEM_APERTURES = 0x00000005,
 KGSL_PROP_MMU_ENABLE = 0x00000006,
 KGSL_PROP_INTERRUPT_WAITS = 0x00000007,
};

struct kgsl_shadowprop {
 unsigned int gpuaddr;
 unsigned int size;
 unsigned int flags;
};

#define KGSL_IOC_TYPE 0x09

struct kgsl_device_getproperty {
 unsigned int type;
 void *value;
 unsigned int sizebytes;
};

#define IOCTL_KGSL_DEVICE_GETPROPERTY   _IOWR(KGSL_IOC_TYPE, 0x2, struct kgsl_device_getproperty)

struct kgsl_device_regread {
 unsigned int offsetwords;
 unsigned int value;
};

#define IOCTL_KGSL_DEVICE_REGREAD   _IOWR(KGSL_IOC_TYPE, 0x3, struct kgsl_device_regread)

struct kgsl_device_waittimestamp {
 unsigned int timestamp;
 unsigned int timeout;
};

#define IOCTL_KGSL_DEVICE_WAITTIMESTAMP   _IOW(KGSL_IOC_TYPE, 0x6, struct kgsl_device_waittimestamp)

struct kgsl_ringbuffer_issueibcmds {
 unsigned int drawctxt_id;
 unsigned int ibaddr;
 unsigned int sizedwords;
 unsigned int timestamp;
 unsigned int flags;
};

#define IOCTL_KGSL_RINGBUFFER_ISSUEIBCMDS   _IOWR(KGSL_IOC_TYPE, 0x10, struct kgsl_ringbuffer_issueibcmds)

struct kgsl_cmdstream_readtimestamp {
 unsigned int type;
 unsigned int timestamp;
};

#define IOCTL_KGSL_CMDSTREAM_READTIMESTAMP   _IOR(KGSL_IOC_TYPE, 0x11, struct kgsl_cmdstream_readtimestamp)

struct kgsl_cmdstream_freememontimestamp {
 unsigned int gpuaddr;
 unsigned int type;
 unsigned int timestamp;
};

#define IOCTL_KGSL_CMDSTREAM_FREEMEMONTIMESTAMP   _IOR(KGSL_IOC_TYPE, 0x12, struct kgsl_cmdstream_freememontimestamp)

struct kgsl_drawctxt_create {
 unsigned int flags;
 unsigned int drawctxt_id;
};

#define IOCTL_KGSL_DRAWCTXT_CREATE   _IOWR(KGSL_IOC_TYPE, 0x13, struct kgsl_drawctxt_create)

struct kgsl_drawctxt_destroy {
 unsigned int drawctxt_id;
};

#define IOCTL_KGSL_DRAWCTXT_DESTROY   _IOW(KGSL_IOC_TYPE, 0x14, struct kgsl_drawctxt_destroy)

struct kgsl_sharedmem_from_pmem {
 int pmem_fd;
 unsigned int gpuaddr;
 unsigned int len;
 unsigned int offset;
};

#define IOCTL_KGSL_SHAREDMEM_FROM_PMEM   _IOWR(KGSL_IOC_TYPE, 0x20, struct kgsl_sharedmem_from_pmem)

struct kgsl_sharedmem_free {
 unsigned int gpuaddr;
};

#define IOCTL_KGSL_SHAREDMEM_FREE   _IOW(KGSL_IOC_TYPE, 0x21, struct kgsl_sharedmem_free)

struct kgsl_gmem_desc {
 unsigned int x;
 unsigned int y;
 unsigned int width;
 unsigned int height;
 unsigned int pitch;
};

struct kgsl_buffer_desc {
 void *hostptr;
 unsigned int gpuaddr;
 int size;
 unsigned int format;
 unsigned int pitch;
 unsigned int enabled;
};

struct kgsl_bind_gmem_shadow {
 unsigned int drawctxt_id;
 struct kgsl_gmem_desc gmem_desc;
 unsigned int shadow_x;
 unsigned int shadow_y;
 struct kgsl_buffer_desc shadow_buffer;
 unsigned int buffer_id;
};

#define IOCTL_KGSL_DRAWCTXT_BIND_GMEM_SHADOW   _IOW(KGSL_IOC_TYPE, 0x22, struct kgsl_bind_gmem_shadow)

struct kgsl_sharedmem_from_vmalloc {
 unsigned int gpuaddr;
 unsigned int hostptr;

 int force_no_low_watermark;
};

#define IOCTL_KGSL_SHAREDMEM_FROM_VMALLOC   _IOWR(KGSL_IOC_TYPE, 0x23, struct kgsl_sharedmem_from_vmalloc)

#define IOCTL_KGSL_SHAREDMEM_FLUSH_CACHE   _IOW(KGSL_IOC_TYPE, 0x24, struct kgsl_sharedmem_free)

struct kgsl_drawctxt_set_bin_base_offset {
 unsigned int drawctxt_id;
 unsigned int offset;
};

#define IOCTL_KGSL_DRAWCTXT_SET_BIN_BASE_OFFSET   _IOW(KGSL_IOC_TYPE, 0x25, struct kgsl_drawctxt_set_bin_base_offset)

#endif

