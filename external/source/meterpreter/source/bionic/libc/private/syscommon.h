/*
 * syscommon.h
 *
 * Common header file for system call stubs
 */

#define __IN_SYS_COMMON
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/syscall.h>

#include <poll.h>
#include <sched.h>
#include <sys/dirent.h>
#include <sys/klog.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/uio.h>
#include <sys/utime.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __i386__
# include <sys/vm86.h>
#endif
