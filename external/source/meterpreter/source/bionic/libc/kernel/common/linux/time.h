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
#ifndef _LINUX_TIME_H
#define _LINUX_TIME_H

#include <linux/types.h>

#ifndef _STRUCT_TIMESPEC
#define _STRUCT_TIMESPEC
struct timespec {
 time_t tv_sec;
 long tv_nsec;
};
#endif

struct timeval {
 time_t tv_sec;
 suseconds_t tv_usec;
};

struct timezone {
 int tz_minuteswest;
 int tz_dsttime;
};

#define NFDBITS __NFDBITS

#define FD_SETSIZE __FD_SETSIZE
#define FD_SET(fd,fdsetp) __FD_SET(fd,fdsetp)
#define FD_CLR(fd,fdsetp) __FD_CLR(fd,fdsetp)
#define FD_ISSET(fd,fdsetp) __FD_ISSET(fd,fdsetp)
#define FD_ZERO(fdsetp) __FD_ZERO(fdsetp)

#define ITIMER_REAL 0
#define ITIMER_VIRTUAL 1
#define ITIMER_PROF 2

struct itimerspec {
 struct timespec it_interval;
 struct timespec it_value;
};

struct itimerval {
 struct timeval it_interval;
 struct timeval it_value;
};

#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
#define CLOCK_PROCESS_CPUTIME_ID 2
#define CLOCK_THREAD_CPUTIME_ID 3

#define CLOCK_SGI_CYCLE 10
#define MAX_CLOCKS 16
#define CLOCKS_MASK (CLOCK_REALTIME | CLOCK_MONOTONIC)
#define CLOCKS_MONO CLOCK_MONOTONIC

#define TIMER_ABSTIME 0x01

#endif
