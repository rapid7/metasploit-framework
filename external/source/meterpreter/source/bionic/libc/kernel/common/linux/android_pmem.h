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
#ifndef _ANDROID_PMEM_H_
#define _ANDROID_PMEM_H_

#define PMEM_IOCTL_MAGIC 'p'
#define PMEM_GET_PHYS _IOW(PMEM_IOCTL_MAGIC, 1, unsigned int)
#define PMEM_MAP _IOW(PMEM_IOCTL_MAGIC, 2, unsigned int)
#define PMEM_GET_SIZE _IOW(PMEM_IOCTL_MAGIC, 3, unsigned int)
#define PMEM_UNMAP _IOW(PMEM_IOCTL_MAGIC, 4, unsigned int)

#define PMEM_ALLOCATE _IOW(PMEM_IOCTL_MAGIC, 5, unsigned int)

#define PMEM_CONNECT _IOW(PMEM_IOCTL_MAGIC, 6, unsigned int)

#define PMEM_GET_TOTAL_SIZE _IOW(PMEM_IOCTL_MAGIC, 7, unsigned int)
#define PMEM_CACHE_FLUSH _IOW(PMEM_IOCTL_MAGIC, 8, unsigned int)

struct android_pmem_platform_data
{
 const char* name;

 unsigned long start;

 unsigned long size;

 unsigned no_allocator;

 unsigned cached;

 unsigned buffered;
};

struct pmem_region {
 unsigned long offset;
 unsigned long len;
};

#endif

