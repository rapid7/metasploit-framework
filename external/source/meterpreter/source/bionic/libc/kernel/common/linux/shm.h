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
#ifndef _LINUX_SHM_H_
#define _LINUX_SHM_H_

#include <linux/ipc.h>
#include <linux/errno.h>
#include <asm/page.h>

#define SHMMAX 0x2000000  
#define SHMMIN 1  
#define SHMMNI 4096  
#define SHMALL (SHMMAX/PAGE_SIZE*(SHMMNI/16))  
#define SHMSEG SHMMNI  

#include <asm/shmparam.h>

struct shmid_ds {
 struct ipc_perm shm_perm;
 int shm_segsz;
 __kernel_time_t shm_atime;
 __kernel_time_t shm_dtime;
 __kernel_time_t shm_ctime;
 __kernel_ipc_pid_t shm_cpid;
 __kernel_ipc_pid_t shm_lpid;
 unsigned short shm_nattch;
 unsigned short shm_unused;
 void *shm_unused2;
 void *shm_unused3;
};

#include <asm/shmbuf.h>

#define SHM_R 0400  
#define SHM_W 0200  

#define SHM_RDONLY 010000  
#define SHM_RND 020000  
#define SHM_REMAP 040000  
#define SHM_EXEC 0100000  

#define SHM_LOCK 11
#define SHM_UNLOCK 12

#define SHM_STAT 13
#define SHM_INFO 14

struct shminfo {
 int shmmax;
 int shmmin;
 int shmmni;
 int shmseg;
 int shmall;
};

struct shm_info {
 int used_ids;
 unsigned long shm_tot;
 unsigned long shm_rss;
 unsigned long shm_swp;
 unsigned long swap_attempts;
 unsigned long swap_successes;
};

#endif
