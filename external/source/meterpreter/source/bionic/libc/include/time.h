/*
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#ifndef _TIME_H_
#define _TIME_H_

#include <sys/cdefs.h>
#include <sys/time.h>

#define __ARCH_SI_UID_T __kernel_uid32_t
#include <asm/siginfo.h>
#undef __ARCH_SI_UID_T

__BEGIN_DECLS

extern time_t   time(time_t *);
extern int      nanosleep(const struct timespec *, struct timespec *);

extern char *strtotimeval(const char *str, struct timeval *tv);

struct tm {
   int     tm_sec;         /* seconds */
   int     tm_min;         /* minutes */
   int     tm_hour;        /* hours */
   int     tm_mday;        /* day of the month */
   int     tm_mon;         /* month */
   int     tm_year;        /* year */
   int     tm_wday;        /* day of the week */
   int     tm_yday;        /* day in the year */
   int     tm_isdst;       /* daylight saving time */

   long int tm_gmtoff;     /* Seconds east of UTC.  */
   const char *tm_zone;    /* Timezone abbreviation.  */

};

/* defining TM_ZONE indicates that we have a "timezone abbreviation" field in
 * struct tm, the value should be the field name
 */
#define   TM_ZONE   tm_zone

extern char* asctime(const struct tm* a);
extern char* asctime_r(const struct tm* a, char* buf);

/* Return the difference between TIME1 and TIME0.  */
extern double difftime (time_t __time1, time_t __time0);
extern time_t mktime (struct tm *a);

extern struct tm*  localtime(const time_t *t);
extern struct tm*  localtime_r(const time_t *timep, struct tm *result);

extern struct tm*  gmtime(const time_t *timep);
extern struct tm*  gmtime_r(const time_t *timep, struct tm *result);

extern char*       strptime(const char *buf, const char *fmt, struct tm *tm);
extern size_t      strftime(char *s, size_t max, const char *format, const struct tm *tm);

/* ANDROID-BEGIN */
struct strftime_locale {
    const char *  mon[12];
    const char *  month[12];
    const char *  standalone_month[12];
    const char *  wday[7];
    const char *  weekday[7];
    const char *  X_fmt;
    const char *  x_fmt;
    const char *  c_fmt;
    const char *  am;
    const char *  pm;
    const char *  date_fmt;
};

extern size_t      strftime_tz(char *s, size_t max, const char *format, const struct tm *tm, const struct strftime_locale*  lc);
/* ANDROID-END */

extern char *ctime(const time_t *timep);
extern char *ctime_r(const time_t *timep, char *buf);

extern void  tzset(void);

/* global includes */
extern char*     tzname[];
extern int       daylight;
extern long int  timezone;

#define CLOCKS_PER_SEC     1000000

extern clock_t   clock(void);

/* BIONIC: extra linux clock goodies */
extern int clock_getres(int, struct timespec *);
extern int clock_gettime(int, struct timespec *);

#define CLOCK_REALTIME             0
#define CLOCK_MONOTONIC            1
#define CLOCK_PROCESS_CPUTIME_ID   2
#define CLOCK_THREAD_CPUTIME_ID    3
#define CLOCK_REALTIME_HR          4
#define CLOCK_MONOTONIC_HR         5

extern int  timer_create(int, struct sigevent*, timer_t*);
extern int  timer_delete(timer_t);
extern int  timer_settime(timer_t timerid, int flags, const struct itimerspec *value, struct itimerspec *ovalue);
extern int  timer_gettime(timer_t timerid, struct itimerspec *value);
extern int  timer_getoverrun(timer_t  timerid);

__END_DECLS

#endif /* _TIME_H_ */
