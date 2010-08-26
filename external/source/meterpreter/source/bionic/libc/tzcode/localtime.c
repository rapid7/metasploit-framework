/*
** This file is in the public domain, so clarified as of
** 1996-06-05 by Arthur David Olson.
*/

#ifndef lint
#ifndef NOID
static char elsieid[] = "@(#)localtime.c    8.3";
#endif /* !defined NOID */
#endif /* !defined lint */

/*
** Leap second handling from Bradley White.
** POSIX-style TZ environment variable handling from Guy Harris.
*/

/*LINTLIBRARY*/

#include "private.h"
#include "tzfile.h"
#include "fcntl.h"
#include "float.h"  /* for FLT_MAX and DBL_MAX */

#include "thread_private.h"
#include <sys/system_properties.h>

#ifndef TZ_ABBR_MAX_LEN
#define TZ_ABBR_MAX_LEN 16
#endif /* !defined TZ_ABBR_MAX_LEN */

#ifndef TZ_ABBR_CHAR_SET
#define TZ_ABBR_CHAR_SET \
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 :+-._"
#endif /* !defined TZ_ABBR_CHAR_SET */

#ifndef TZ_ABBR_ERR_CHAR
#define TZ_ABBR_ERR_CHAR    '_'
#endif /* !defined TZ_ABBR_ERR_CHAR */

#define INDEXFILE "/system/usr/share/zoneinfo/zoneinfo.idx"
#define DATAFILE "/system/usr/share/zoneinfo/zoneinfo.dat"
#define NAMELEN 40
#define INTLEN 4
#define READLEN (NAMELEN + 3 * INTLEN)

/*
** SunOS 4.1.1 headers lack O_BINARY.
*/

#ifdef O_BINARY
#define OPEN_MODE   (O_RDONLY | O_BINARY)
#endif /* defined O_BINARY */
#ifndef O_BINARY
#define OPEN_MODE   O_RDONLY
#endif /* !defined O_BINARY */

#if 0
#  define  XLOG(xx)  printf xx , fflush(stdout)
#else
#  define  XLOG(x)   do{}while (0)
#endif

/* THREAD-SAFETY SUPPORT GOES HERE */
static pthread_mutex_t  _tzMutex = PTHREAD_MUTEX_INITIALIZER;

static __inline__ void _tzLock(void)
{
    if (__isthreaded)
        pthread_mutex_lock(&_tzMutex);
}

static __inline__ void _tzUnlock(void)
{
    if (__isthreaded)
        pthread_mutex_unlock(&_tzMutex);
}

/* Complex computations to determine the min/max of time_t depending
 * on TYPE_BIT / TYPE_SIGNED / TYPE_INTEGRAL.
 * These macros cannot be used in pre-processor directives, so we
 * let the C compiler do the work, which makes things a bit funky.
 */
static const time_t TIME_T_MAX =
    TYPE_INTEGRAL(time_t) ?
        ( TYPE_SIGNED(time_t) ?
            ~((time_t)1 << (TYPE_BIT(time_t)-1))
        :
            ~(time_t)0
        )
    : /* if time_t is a floating point number */
        ( sizeof(time_t) > sizeof(float) ? (time_t)DBL_MAX : (time_t)FLT_MAX );

static const time_t TIME_T_MIN =
    TYPE_INTEGRAL(time_t) ?
        ( TYPE_SIGNED(time_t) ?
            ((time_t)1 << (TYPE_BIT(time_t)-1))
        :
            0
        )
    :
        ( sizeof(time_t) > sizeof(float) ? (time_t)DBL_MIN : (time_t)FLT_MIN );

#ifndef WILDABBR
/*
** Someone might make incorrect use of a time zone abbreviation:
**  1.  They might reference tzname[0] before calling tzset (explicitly
**      or implicitly).
**  2.  They might reference tzname[1] before calling tzset (explicitly
**      or implicitly).
**  3.  They might reference tzname[1] after setting to a time zone
**      in which Daylight Saving Time is never observed.
**  4.  They might reference tzname[0] after setting to a time zone
**      in which Standard Time is never observed.
**  5.  They might reference tm.TM_ZONE after calling offtime.
** What's best to do in the above cases is open to debate;
** for now, we just set things up so that in any of the five cases
** WILDABBR is used. Another possibility: initialize tzname[0] to the
** string "tzname[0] used before set", and similarly for the other cases.
** And another: initialize tzname[0] to "ERA", with an explanation in the
** manual page of what this "time zone abbreviation" means (doing this so
** that tzname[0] has the "normal" length of three characters).
*/
#define WILDABBR    "   "
#endif /* !defined WILDABBR */

static char     wildabbr[] = WILDABBR;

static const char   gmt[] = "GMT";

/*
** The DST rules to use if TZ has no rules and we can't load TZDEFRULES.
** We default to US rules as of 1999-08-17.
** POSIX 1003.1 section 8.1.1 says that the default DST rules are
** implementation dependent; for historical reasons, US rules are a
** common default.
*/
#ifndef TZDEFRULESTRING
#define TZDEFRULESTRING ",M4.1.0,M10.5.0"
#endif /* !defined TZDEFDST */

struct ttinfo {             /* time type information */
    long    tt_gmtoff;  /* UTC offset in seconds */
    int     tt_isdst;   /* used to set tm_isdst */
    int     tt_abbrind; /* abbreviation list index */
    int     tt_ttisstd; /* TRUE if transition is std time */
    int     tt_ttisgmt; /* TRUE if transition is UTC */
};

struct lsinfo {             /* leap second information */
    time_t      ls_trans;   /* transition time */
    long        ls_corr;    /* correction to apply */
};

#define BIGGEST(a, b)   (((a) > (b)) ? (a) : (b))

#ifdef TZNAME_MAX
#define MY_TZNAME_MAX   TZNAME_MAX
#endif /* defined TZNAME_MAX */
#ifndef TZNAME_MAX
#define MY_TZNAME_MAX   255
#endif /* !defined TZNAME_MAX */

/* XXX: This code should really use time64_t instead of time_t
 *      but we can't change it without re-generating the index
 *      file first with the correct data.
 */
struct state {
    int     leapcnt;
    int     timecnt;
    int     typecnt;
    int     charcnt;
    int     goback;
    int     goahead;
    time_t      ats[TZ_MAX_TIMES];
    unsigned char   types[TZ_MAX_TIMES];
    struct ttinfo   ttis[TZ_MAX_TYPES];
    char        chars[BIGGEST(BIGGEST(TZ_MAX_CHARS + 1, sizeof gmt),
                (2 * (MY_TZNAME_MAX + 1)))];
    struct lsinfo   lsis[TZ_MAX_LEAPS];
};

struct rule {
    int     r_type;     /* type of rule--see below */
    int     r_day;      /* day number of rule */
    int     r_week;     /* week number of rule */
    int     r_mon;      /* month number of rule */
    long        r_time;     /* transition time of rule */
};

#define JULIAN_DAY      0   /* Jn - Julian day */
#define DAY_OF_YEAR     1   /* n - day of year */
#define MONTH_NTH_DAY_OF_WEEK   2   /* Mm.n.d - month, week, day of week */

/*
** Prototypes for static functions.
*/

/* NOTE: all internal functions assume that _tzLock() was already called */

static long     detzcode P((const char * codep));
static time_t   detzcode64 P((const char * codep));
static int      differ_by_repeat P((time_t t1, time_t t0));
static const char * getzname P((const char * strp));
static const char * getqzname P((const char * strp, const int delim));
static const char * getnum P((const char * strp, int * nump, int min,
                int max));
static const char * getsecs P((const char * strp, long * secsp));
static const char * getoffset P((const char * strp, long * offsetp));
static const char * getrule P((const char * strp, struct rule * rulep));
static void     gmtload P((struct state * sp));
static struct tm *  gmtsub P((const time_t * timep, long offset,
                struct tm * tmp));
static struct tm *  localsub P((const time_t * timep, long offset,
                struct tm * tmp));
static int      increment_overflow P((int * number, int delta));
static int      leaps_thru_end_of P((int y));
static int      long_increment_overflow P((long * number, int delta));
static int      long_normalize_overflow P((long * tensptr,
                int * unitsptr, int base));
static int      normalize_overflow P((int * tensptr, int * unitsptr,
                int base));
static void     settzname P((void));
static time_t       time1 P((struct tm * tmp,
                struct tm * (*funcp) P((const time_t *,
                long, struct tm *)),
                long offset));
static time_t       time2 P((struct tm *tmp,
                struct tm * (*funcp) P((const time_t *,
                long, struct tm*)),
                long offset, int * okayp));
static time_t       time2sub P((struct tm *tmp,
                struct tm * (*funcp) P((const time_t *,
                long, struct tm*)),
                long offset, int * okayp, int do_norm_secs));
static struct tm *  timesub P((const time_t * timep, long offset,
                const struct state * sp, struct tm * tmp));
static int      tmcomp P((const struct tm * atmp,
                const struct tm * btmp));
static time_t       transtime P((time_t janfirst, int year,
                const struct rule * rulep, long offset));
static int      tzload P((const char * name, struct state * sp,
                int doextend));
static int      tzparse P((const char * name, struct state * sp,
                int lastditch));

#ifdef ALL_STATE
static struct state *   lclptr;
static struct state *   gmtptr;
#endif /* defined ALL_STATE */

#ifndef ALL_STATE
static struct state lclmem;
static struct state gmtmem;
#define lclptr      (&lclmem)
#define gmtptr      (&gmtmem)
#endif /* State Farm */

#ifndef TZ_STRLEN_MAX
#define TZ_STRLEN_MAX 255
#endif /* !defined TZ_STRLEN_MAX */

static char     lcl_TZname[TZ_STRLEN_MAX + 1];
static int      lcl_is_set;
static int      gmt_is_set;

char *          tzname[2] = {
    wildabbr,
    wildabbr
};

/*
** Section 4.12.3 of X3.159-1989 requires that
**  Except for the strftime function, these functions [asctime,
**  ctime, gmtime, localtime] return values in one of two static
**  objects: a broken-down time structure and an array of char.
** Thanks to Paul Eggert for noting this.
*/

static struct tm    tmGlobal;

#ifdef USG_COMPAT
time_t          timezone = 0;
int         daylight = 0;
#endif /* defined USG_COMPAT */

#ifdef ALTZONE
time_t          altzone = 0;
#endif /* defined ALTZONE */

static long
detzcode(codep)
const char * const  codep;
{
    register long   result;
    register int    i;

    result = (codep[0] & 0x80) ? ~0L : 0;
    for (i = 0; i < 4; ++i)
        result = (result << 8) | (codep[i] & 0xff);
    return result;
}

static time_t
detzcode64(codep)
const char * const  codep;
{
    register time_t result;
    register int    i;

    result = (codep[0] & 0x80) ?  (~(int_fast64_t) 0) : 0;
    for (i = 0; i < 8; ++i)
        result = result * 256 + (codep[i] & 0xff);
    return result;
}

static void
settzname P((void))
{
    register struct state * const   sp = lclptr;
    register int            i;

    tzname[0] = wildabbr;
    tzname[1] = wildabbr;
#ifdef USG_COMPAT
    daylight = 0;
    timezone = 0;
#endif /* defined USG_COMPAT */
#ifdef ALTZONE
    altzone = 0;
#endif /* defined ALTZONE */
#ifdef ALL_STATE
    if (sp == NULL) {
        tzname[0] = tzname[1] = gmt;
        return;
    }
#endif /* defined ALL_STATE */
    for (i = 0; i < sp->typecnt; ++i) {
        register const struct ttinfo * const    ttisp = &sp->ttis[i];

        tzname[ttisp->tt_isdst] =
            &sp->chars[ttisp->tt_abbrind];
#ifdef USG_COMPAT
        if (ttisp->tt_isdst)
            daylight = 1;
        if (i == 0 || !ttisp->tt_isdst)
            timezone = -(ttisp->tt_gmtoff);
#endif /* defined USG_COMPAT */
#ifdef ALTZONE
        if (i == 0 || ttisp->tt_isdst)
            altzone = -(ttisp->tt_gmtoff);
#endif /* defined ALTZONE */
    }
    /*
    ** And to get the latest zone names into tzname. . .
    */
    for (i = 0; i < sp->timecnt; ++i) {
        register const struct ttinfo * const    ttisp =
                            &sp->ttis[
                                sp->types[i]];

        tzname[ttisp->tt_isdst] =
            &sp->chars[ttisp->tt_abbrind];
    }
    /*
    ** Finally, scrub the abbreviations.
    ** First, replace bogus characters.
    */
    for (i = 0; i < sp->charcnt; ++i)
        if (strchr(TZ_ABBR_CHAR_SET, sp->chars[i]) == NULL)
            sp->chars[i] = TZ_ABBR_ERR_CHAR;
    /*
    ** Second, truncate long abbreviations.
    */
    for (i = 0; i < sp->typecnt; ++i) {
        register const struct ttinfo * const    ttisp = &sp->ttis[i];
        register char *             cp = &sp->chars[ttisp->tt_abbrind];

        if (strlen(cp) > TZ_ABBR_MAX_LEN &&
            strcmp(cp, GRANDPARENTED) != 0)
                *(cp + TZ_ABBR_MAX_LEN) = '\0';
    }
}

static int
differ_by_repeat(t1, t0)
const time_t    t1;
const time_t    t0;
{
    if (TYPE_INTEGRAL(time_t) &&
        TYPE_BIT(time_t) - TYPE_SIGNED(time_t) < SECSPERREPEAT_BITS)
            return 0;
        return (t1 - t0) == SECSPERREPEAT;
}

static int toint(unsigned char *s) {
    return (s[0] << 24) | (s[1] << 16) | (s[2] << 8) | s[3];
}

static int
tzload(name, sp, doextend)
register const char *       name;
register struct state * const   sp;
register const int      doextend;
{
    register const char *       p;
    register int            i;
    register int            fid;
    register int            stored;
    register int            nread;
    union {
        struct tzhead   tzhead;
        char        buf[2 * sizeof(struct tzhead) +
                    2 * sizeof *sp +
                    4 * TZ_MAX_TIMES];
    } u;
    int                     toread = sizeof u.buf;

        if (name == NULL && (name = TZDEFAULT) == NULL) {
                XLOG(("tzload: null 'name' parameter\n" ));
                return -1;
        }
    {
        register int    doaccess;
        /*
        ** Section 4.9.1 of the C standard says that
        ** "FILENAME_MAX expands to an integral constant expression
        ** that is the size needed for an array of char large enough
        ** to hold the longest file name string that the implementation
        ** guarantees can be opened."
        */
        char        fullname[FILENAME_MAX + 1];
        char        *origname = (char*) name;

        if (name[0] == ':')
            ++name;
        doaccess = name[0] == '/';
        if (!doaccess) {
            if ((p = TZDIR) == NULL) {
                XLOG(("tzload: null TZDIR macro ?\n" ));
                return -1;
            }
            if ((strlen(p) + strlen(name) + 1) >= sizeof fullname) {
                XLOG(( "tzload: path too long: %s/%s\n", p, name ));
                return -1;
            }
            (void) strcpy(fullname, p);
            (void) strcat(fullname, "/");
            (void) strcat(fullname, name);
            /*
            ** Set doaccess if '.' (as in "../") shows up in name.
            */
            if (strchr(name, '.') != NULL)
                doaccess = TRUE;
            name = fullname;
        }
        if (doaccess && access(name, R_OK) != 0) {
            XLOG(( "tzload: could not find '%s'\n", name ));
            return -1;
        }
        if ((fid = open(name, OPEN_MODE)) == -1) {
            char buf[READLEN];
            char name[NAMELEN + 1];
            int fidix = open(INDEXFILE, OPEN_MODE);
            int off = -1;

            XLOG(( "tzload: could not open '%s', trying '%s'\n", fullname, INDEXFILE ));
            if (fidix < 0) {
                XLOG(( "tzload: could not find '%s'\n", INDEXFILE ));
                return -1;
            }

            while (read(fidix, buf, sizeof(buf)) == sizeof(buf)) {
                memcpy(name, buf, NAMELEN);
                name[NAMELEN] = '\0';

                if (strcmp(name, origname) == 0) {
                    off = toint((unsigned char *) buf + NAMELEN);
                    toread = toint((unsigned char *) buf + NAMELEN + INTLEN);
                    break;
                }
            }

            close(fidix);

            if (off < 0) {
                XLOG(( "tzload: invalid offset (%d)\n", off ));
                return -1;
            }

            fid = open(DATAFILE, OPEN_MODE);

            if (fid < 0) {
                XLOG(( "tzload: could not open '%s'\n", DATAFILE ));
                return -1;
            }

            if (lseek(fid, off, SEEK_SET) < 0) {
                XLOG(( "tzload: could not seek to %d in '%s'\n", off, DATAFILE ));
                return -1;
            }
        }
    }
    nread = read(fid, u.buf, toread);
        if (close(fid) < 0 || nread <= 0) {
            XLOG(( "tzload: could not read content of '%s'\n", DATAFILE ));
            return -1;
        }
    for (stored = 4; stored <= 8; stored *= 2) {
        int     ttisstdcnt;
        int     ttisgmtcnt;

        ttisstdcnt = (int) detzcode(u.tzhead.tzh_ttisstdcnt);
        ttisgmtcnt = (int) detzcode(u.tzhead.tzh_ttisgmtcnt);
        sp->leapcnt = (int) detzcode(u.tzhead.tzh_leapcnt);
        sp->timecnt = (int) detzcode(u.tzhead.tzh_timecnt);
        sp->typecnt = (int) detzcode(u.tzhead.tzh_typecnt);
        sp->charcnt = (int) detzcode(u.tzhead.tzh_charcnt);
        p = u.tzhead.tzh_charcnt + sizeof u.tzhead.tzh_charcnt;
        if (sp->leapcnt < 0 || sp->leapcnt > TZ_MAX_LEAPS ||
            sp->typecnt <= 0 || sp->typecnt > TZ_MAX_TYPES ||
            sp->timecnt < 0 || sp->timecnt > TZ_MAX_TIMES ||
            sp->charcnt < 0 || sp->charcnt > TZ_MAX_CHARS ||
            (ttisstdcnt != sp->typecnt && ttisstdcnt != 0) ||
            (ttisgmtcnt != sp->typecnt && ttisgmtcnt != 0))
                return -1;
        if (nread - (p - u.buf) <
            sp->timecnt * stored +      /* ats */
            sp->timecnt +           /* types */
            sp->typecnt * 6 +       /* ttinfos */
            sp->charcnt +           /* chars */
            sp->leapcnt * (stored + 4) +    /* lsinfos */
            ttisstdcnt +            /* ttisstds */
            ttisgmtcnt)         /* ttisgmts */
                return -1;
        for (i = 0; i < sp->timecnt; ++i) {
            sp->ats[i] = (stored == 4) ?
                detzcode(p) : detzcode64(p);
            p += stored;
        }
        for (i = 0; i < sp->timecnt; ++i) {
            sp->types[i] = (unsigned char) *p++;
            if (sp->types[i] >= sp->typecnt)
                return -1;
        }
        for (i = 0; i < sp->typecnt; ++i) {
            register struct ttinfo *    ttisp;

            ttisp = &sp->ttis[i];
            ttisp->tt_gmtoff = detzcode(p);
            p += 4;
            ttisp->tt_isdst = (unsigned char) *p++;
            if (ttisp->tt_isdst != 0 && ttisp->tt_isdst != 1)
                return -1;
            ttisp->tt_abbrind = (unsigned char) *p++;
            if (ttisp->tt_abbrind < 0 ||
                ttisp->tt_abbrind > sp->charcnt)
                    return -1;
        }
        for (i = 0; i < sp->charcnt; ++i)
            sp->chars[i] = *p++;
        sp->chars[i] = '\0';    /* ensure '\0' at end */
        for (i = 0; i < sp->leapcnt; ++i) {
            register struct lsinfo *    lsisp;

            lsisp = &sp->lsis[i];
            lsisp->ls_trans = (stored == 4) ?
                detzcode(p) : detzcode64(p);
            p += stored;
            lsisp->ls_corr = detzcode(p);
            p += 4;
        }
        for (i = 0; i < sp->typecnt; ++i) {
            register struct ttinfo *    ttisp;

            ttisp = &sp->ttis[i];
            if (ttisstdcnt == 0)
                ttisp->tt_ttisstd = FALSE;
            else {
                ttisp->tt_ttisstd = *p++;
                if (ttisp->tt_ttisstd != TRUE &&
                    ttisp->tt_ttisstd != FALSE)
                        return -1;
            }
        }
        for (i = 0; i < sp->typecnt; ++i) {
            register struct ttinfo *    ttisp;

            ttisp = &sp->ttis[i];
            if (ttisgmtcnt == 0)
                ttisp->tt_ttisgmt = FALSE;
            else {
                ttisp->tt_ttisgmt = *p++;
                if (ttisp->tt_ttisgmt != TRUE &&
                    ttisp->tt_ttisgmt != FALSE)
                        return -1;
            }
        }
        /*
        ** Out-of-sort ats should mean we're running on a
        ** signed time_t system but using a data file with
        ** unsigned values (or vice versa).
        */
        for (i = 0; i < sp->timecnt - 2; ++i)
            if (sp->ats[i] > sp->ats[i + 1]) {
                ++i;
                if (TYPE_SIGNED(time_t)) {
                    /*
                    ** Ignore the end (easy).
                    */
                    sp->timecnt = i;
                } else {
                    /*
                    ** Ignore the beginning (harder).
                    */
                    register int    j;

                    for (j = 0; j + i < sp->timecnt; ++j) {
                        sp->ats[j] = sp->ats[j + i];
                        sp->types[j] = sp->types[j + i];
                    }
                    sp->timecnt = j;
                }
                break;
            }
        /*
        ** If this is an old file, we're done.
        */
        if (u.tzhead.tzh_version[0] == '\0')
            break;
        nread -= p - u.buf;
        for (i = 0; i < nread; ++i)
            u.buf[i] = p[i];
        /*
        ** If this is a narrow integer time_t system, we're done.
        */
        if (stored >= (int) sizeof(time_t) && TYPE_INTEGRAL(time_t))
            break;
    }
    if (doextend && nread > 2 &&
        u.buf[0] == '\n' && u.buf[nread - 1] == '\n' &&
        sp->typecnt + 2 <= TZ_MAX_TYPES) {
            struct state    ts;
            register int    result;

            u.buf[nread - 1] = '\0';
            result = tzparse(&u.buf[1], &ts, FALSE);
            if (result == 0 && ts.typecnt == 2 &&
                sp->charcnt + ts.charcnt <= TZ_MAX_CHARS) {
                    for (i = 0; i < 2; ++i)
                        ts.ttis[i].tt_abbrind +=
                            sp->charcnt;
                    for (i = 0; i < ts.charcnt; ++i)
                        sp->chars[sp->charcnt++] =
                            ts.chars[i];
                    i = 0;
                    while (i < ts.timecnt &&
                        ts.ats[i] <=
                        sp->ats[sp->timecnt - 1])
                            ++i;
                    while (i < ts.timecnt &&
                        sp->timecnt < TZ_MAX_TIMES) {
                        sp->ats[sp->timecnt] =
                            ts.ats[i];
                        sp->types[sp->timecnt] =
                            sp->typecnt +
                            ts.types[i];
                        ++sp->timecnt;
                        ++i;
                    }
                    sp->ttis[sp->typecnt++] = ts.ttis[0];
                    sp->ttis[sp->typecnt++] = ts.ttis[1];
            }
    }
    i = 2 * YEARSPERREPEAT;
    sp->goback = sp->goahead = sp->timecnt > i;
    sp->goback &= sp->types[i] == sp->types[0] &&
        differ_by_repeat(sp->ats[i], sp->ats[0]);
    sp->goahead &=
        sp->types[sp->timecnt - 1] == sp->types[sp->timecnt - 1 - i] &&
        differ_by_repeat(sp->ats[sp->timecnt - 1],
             sp->ats[sp->timecnt - 1 - i]);
        XLOG(( "tzload: load ok !!\n" ));
    return 0;
}

static const int    mon_lengths[2][MONSPERYEAR] = {
    { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
    { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
};

static const int    year_lengths[2] = {
    DAYSPERNYEAR, DAYSPERLYEAR
};

/*
** Given a pointer into a time zone string, scan until a character that is not
** a valid character in a zone name is found. Return a pointer to that
** character.
*/

static const char *
getzname(strp)
register const char *   strp;
{
    register char   c;

    while ((c = *strp) != '\0' && !is_digit(c) && c != ',' && c != '-' &&
        c != '+')
            ++strp;
    return strp;
}

/*
** Given a pointer into an extended time zone string, scan until the ending
** delimiter of the zone name is located. Return a pointer to the delimiter.
**
** As with getzname above, the legal character set is actually quite
** restricted, with other characters producing undefined results.
** We don't do any checking here; checking is done later in common-case code.
*/

static const char *
getqzname(register const char *strp, const int delim)
{
    register int    c;

    while ((c = *strp) != '\0' && c != delim)
        ++strp;
    return strp;
}

/*
** Given a pointer into a time zone string, extract a number from that string.
** Check that the number is within a specified range; if it is not, return
** NULL.
** Otherwise, return a pointer to the first character not part of the number.
*/

static const char *
getnum(strp, nump, min, max)
register const char *   strp;
int * const     nump;
const int       min;
const int       max;
{
    register char   c;
    register int    num;

    if (strp == NULL || !is_digit(c = *strp))
        return NULL;
    num = 0;
    do {
        num = num * 10 + (c - '0');
        if (num > max)
            return NULL;    /* illegal value */
        c = *++strp;
    } while (is_digit(c));
    if (num < min)
        return NULL;        /* illegal value */
    *nump = num;
    return strp;
}

/*
** Given a pointer into a time zone string, extract a number of seconds,
** in hh[:mm[:ss]] form, from the string.
** If any error occurs, return NULL.
** Otherwise, return a pointer to the first character not part of the number
** of seconds.
*/

static const char *
getsecs(strp, secsp)
register const char *   strp;
long * const        secsp;
{
    int num;

    /*
    ** `HOURSPERDAY * DAYSPERWEEK - 1' allows quasi-Posix rules like
    ** "M10.4.6/26", which does not conform to Posix,
    ** but which specifies the equivalent of
    ** ``02:00 on the first Sunday on or after 23 Oct''.
    */
    strp = getnum(strp, &num, 0, HOURSPERDAY * DAYSPERWEEK - 1);
    if (strp == NULL)
        return NULL;
    *secsp = num * (long) SECSPERHOUR;
    if (*strp == ':') {
        ++strp;
        strp = getnum(strp, &num, 0, MINSPERHOUR - 1);
        if (strp == NULL)
            return NULL;
        *secsp += num * SECSPERMIN;
        if (*strp == ':') {
            ++strp;
            /* `SECSPERMIN' allows for leap seconds. */
            strp = getnum(strp, &num, 0, SECSPERMIN);
            if (strp == NULL)
                return NULL;
            *secsp += num;
        }
    }
    return strp;
}

/*
** Given a pointer into a time zone string, extract an offset, in
** [+-]hh[:mm[:ss]] form, from the string.
** If any error occurs, return NULL.
** Otherwise, return a pointer to the first character not part of the time.
*/

static const char *
getoffset(strp, offsetp)
register const char *   strp;
long * const        offsetp;
{
    register int    neg = 0;

    if (*strp == '-') {
        neg = 1;
        ++strp;
    } else if (*strp == '+')
        ++strp;
    strp = getsecs(strp, offsetp);
    if (strp == NULL)
        return NULL;        /* illegal time */
    if (neg)
        *offsetp = -*offsetp;
    return strp;
}

/*
** Given a pointer into a time zone string, extract a rule in the form
** date[/time]. See POSIX section 8 for the format of "date" and "time".
** If a valid rule is not found, return NULL.
** Otherwise, return a pointer to the first character not part of the rule.
*/

static const char *
getrule(strp, rulep)
const char *            strp;
register struct rule * const    rulep;
{
    if (*strp == 'J') {
        /*
        ** Julian day.
        */
        rulep->r_type = JULIAN_DAY;
        ++strp;
        strp = getnum(strp, &rulep->r_day, 1, DAYSPERNYEAR);
    } else if (*strp == 'M') {
        /*
        ** Month, week, day.
        */
        rulep->r_type = MONTH_NTH_DAY_OF_WEEK;
        ++strp;
        strp = getnum(strp, &rulep->r_mon, 1, MONSPERYEAR);
        if (strp == NULL)
            return NULL;
        if (*strp++ != '.')
            return NULL;
        strp = getnum(strp, &rulep->r_week, 1, 5);
        if (strp == NULL)
            return NULL;
        if (*strp++ != '.')
            return NULL;
        strp = getnum(strp, &rulep->r_day, 0, DAYSPERWEEK - 1);
    } else if (is_digit(*strp)) {
        /*
        ** Day of year.
        */
        rulep->r_type = DAY_OF_YEAR;
        strp = getnum(strp, &rulep->r_day, 0, DAYSPERLYEAR - 1);
    } else  return NULL;        /* invalid format */
    if (strp == NULL)
        return NULL;
    if (*strp == '/') {
        /*
        ** Time specified.
        */
        ++strp;
        strp = getsecs(strp, &rulep->r_time);
    } else  rulep->r_time = 2 * SECSPERHOUR;    /* default = 2:00:00 */
    return strp;
}

/*
** Given the Epoch-relative time of January 1, 00:00:00 UTC, in a year, the
** year, a rule, and the offset from UTC at the time that rule takes effect,
** calculate the Epoch-relative time that rule takes effect.
*/

static time_t
transtime(janfirst, year, rulep, offset)
const time_t                janfirst;
const int               year;
register const struct rule * const  rulep;
const long              offset;
{
    register int    leapyear;
    register time_t value;
    register int    i;
    int     d, m1, yy0, yy1, yy2, dow;

    INITIALIZE(value);
    leapyear = isleap(year);
    switch (rulep->r_type) {

    case JULIAN_DAY:
        /*
        ** Jn - Julian day, 1 == January 1, 60 == March 1 even in leap
        ** years.
        ** In non-leap years, or if the day number is 59 or less, just
        ** add SECSPERDAY times the day number-1 to the time of
        ** January 1, midnight, to get the day.
        */
        value = janfirst + (rulep->r_day - 1) * SECSPERDAY;
        if (leapyear && rulep->r_day >= 60)
            value += SECSPERDAY;
        break;

    case DAY_OF_YEAR:
        /*
        ** n - day of year.
        ** Just add SECSPERDAY times the day number to the time of
        ** January 1, midnight, to get the day.
        */
        value = janfirst + rulep->r_day * SECSPERDAY;
        break;

    case MONTH_NTH_DAY_OF_WEEK:
        /*
        ** Mm.n.d - nth "dth day" of month m.
        */
        value = janfirst;
        for (i = 0; i < rulep->r_mon - 1; ++i)
            value += mon_lengths[leapyear][i] * SECSPERDAY;

        /*
        ** Use Zeller's Congruence to get day-of-week of first day of
        ** month.
        */
        m1 = (rulep->r_mon + 9) % 12 + 1;
        yy0 = (rulep->r_mon <= 2) ? (year - 1) : year;
        yy1 = yy0 / 100;
        yy2 = yy0 % 100;
        dow = ((26 * m1 - 2) / 10 +
            1 + yy2 + yy2 / 4 + yy1 / 4 - 2 * yy1) % 7;
        if (dow < 0)
            dow += DAYSPERWEEK;

        /*
        ** "dow" is the day-of-week of the first day of the month. Get
        ** the day-of-month (zero-origin) of the first "dow" day of the
        ** month.
        */
        d = rulep->r_day - dow;
        if (d < 0)
            d += DAYSPERWEEK;
        for (i = 1; i < rulep->r_week; ++i) {
            if (d + DAYSPERWEEK >=
                mon_lengths[leapyear][rulep->r_mon - 1])
                    break;
            d += DAYSPERWEEK;
        }

        /*
        ** "d" is the day-of-month (zero-origin) of the day we want.
        */
        value += d * SECSPERDAY;
        break;
    }

    /*
    ** "value" is the Epoch-relative time of 00:00:00 UTC on the day in
    ** question. To get the Epoch-relative time of the specified local
    ** time on that day, add the transition time and the current offset
    ** from UTC.
    */
    return value + rulep->r_time + offset;
}

/*
** Given a POSIX section 8-style TZ string, fill in the rule tables as
** appropriate.
*/

static int
tzparse(name, sp, lastditch)
const char *            name;
register struct state * const   sp;
const int           lastditch;
{
    const char *            stdname;
    const char *            dstname;
    size_t              stdlen;
    size_t              dstlen;
    long                stdoffset;
    long                dstoffset;
    register time_t *       atp;
    register unsigned char *    typep;
    register char *         cp;
    register int            load_result;

    INITIALIZE(dstname);
    stdname = name;
    if (lastditch) {
        stdlen = strlen(name);  /* length of standard zone name */
        name += stdlen;
        if (stdlen >= sizeof sp->chars)
            stdlen = (sizeof sp->chars) - 1;
        stdoffset = 0;
    } else {
        if (*name == '<') {
            name++;
            stdname = name;
            name = getqzname(name, '>');
            if (*name != '>')
                return (-1);
            stdlen = name - stdname;
            name++;
        } else {
            name = getzname(name);
            stdlen = name - stdname;
        }
        if (*name == '\0')
            return -1;
        name = getoffset(name, &stdoffset);
        if (name == NULL)
            return -1;
    }
    load_result = tzload(TZDEFRULES, sp, FALSE);
    if (load_result != 0)
        sp->leapcnt = 0;        /* so, we're off a little */
    sp->timecnt = 0;
    if (*name != '\0') {
        if (*name == '<') {
            dstname = ++name;
            name = getqzname(name, '>');
            if (*name != '>')
                return -1;
            dstlen = name - dstname;
            name++;
        } else {
            dstname = name;
            name = getzname(name);
            dstlen = name - dstname; /* length of DST zone name */
        }
        if (*name != '\0' && *name != ',' && *name != ';') {
            name = getoffset(name, &dstoffset);
            if (name == NULL)
                return -1;
        } else  dstoffset = stdoffset - SECSPERHOUR;
        if (*name == '\0' && load_result != 0)
            name = TZDEFRULESTRING;
        if (*name == ',' || *name == ';') {
            struct rule start;
            struct rule end;
            register int    year;
            register time_t janfirst;
            time_t      starttime;
            time_t      endtime;

            ++name;
            if ((name = getrule(name, &start)) == NULL)
                return -1;
            if (*name++ != ',')
                return -1;
            if ((name = getrule(name, &end)) == NULL)
                return -1;
            if (*name != '\0')
                return -1;
            sp->typecnt = 2;    /* standard time and DST */
            /*
            ** Two transitions per year, from EPOCH_YEAR forward.
            */
            sp->ttis[0].tt_gmtoff = -dstoffset;
            sp->ttis[0].tt_isdst = 1;
            sp->ttis[0].tt_abbrind = stdlen + 1;
            sp->ttis[1].tt_gmtoff = -stdoffset;
            sp->ttis[1].tt_isdst = 0;
            sp->ttis[1].tt_abbrind = 0;
            atp = sp->ats;
            typep = sp->types;
            janfirst = 0;
            for (year = EPOCH_YEAR;
                sp->timecnt + 2 <= TZ_MAX_TIMES;
                ++year) {
                    time_t  newfirst;

                starttime = transtime(janfirst, year, &start,
                    stdoffset);
                endtime = transtime(janfirst, year, &end,
                    dstoffset);
                if (starttime > endtime) {
                    *atp++ = endtime;
                    *typep++ = 1;   /* DST ends */
                    *atp++ = starttime;
                    *typep++ = 0;   /* DST begins */
                } else {
                    *atp++ = starttime;
                    *typep++ = 0;   /* DST begins */
                    *atp++ = endtime;
                    *typep++ = 1;   /* DST ends */
                }
                sp->timecnt += 2;
                newfirst = janfirst;
                newfirst += year_lengths[isleap(year)] *
                    SECSPERDAY;
                if (newfirst <= janfirst)
                    break;
                janfirst = newfirst;
            }
        } else {
            register long   theirstdoffset;
            register long   theirdstoffset;
            register long   theiroffset;
            register int    isdst;
            register int    i;
            register int    j;

            if (*name != '\0')
                return -1;
            /*
            ** Initial values of theirstdoffset and theirdstoffset.
            */
            theirstdoffset = 0;
            for (i = 0; i < sp->timecnt; ++i) {
                j = sp->types[i];
                if (!sp->ttis[j].tt_isdst) {
                    theirstdoffset =
                        -sp->ttis[j].tt_gmtoff;
                    break;
                }
            }
            theirdstoffset = 0;
            for (i = 0; i < sp->timecnt; ++i) {
                j = sp->types[i];
                if (sp->ttis[j].tt_isdst) {
                    theirdstoffset =
                        -sp->ttis[j].tt_gmtoff;
                    break;
                }
            }
            /*
            ** Initially we're assumed to be in standard time.
            */
            isdst = FALSE;
            theiroffset = theirstdoffset;
            /*
            ** Now juggle transition times and types
            ** tracking offsets as you do.
            */
            for (i = 0; i < sp->timecnt; ++i) {
                j = sp->types[i];
                sp->types[i] = sp->ttis[j].tt_isdst;
                if (sp->ttis[j].tt_ttisgmt) {
                    /* No adjustment to transition time */
                } else {
                    /*
                    ** If summer time is in effect, and the
                    ** transition time was not specified as
                    ** standard time, add the summer time
                    ** offset to the transition time;
                    ** otherwise, add the standard time
                    ** offset to the transition time.
                    */
                    /*
                    ** Transitions from DST to DDST
                    ** will effectively disappear since
                    ** POSIX provides for only one DST
                    ** offset.
                    */
                    if (isdst && !sp->ttis[j].tt_ttisstd) {
                        sp->ats[i] += dstoffset -
                            theirdstoffset;
                    } else {
                        sp->ats[i] += stdoffset -
                            theirstdoffset;
                    }
                }
                theiroffset = -sp->ttis[j].tt_gmtoff;
                if (sp->ttis[j].tt_isdst)
                    theirdstoffset = theiroffset;
                else    theirstdoffset = theiroffset;
            }
            /*
            ** Finally, fill in ttis.
            ** ttisstd and ttisgmt need not be handled.
            */
            sp->ttis[0].tt_gmtoff = -stdoffset;
            sp->ttis[0].tt_isdst = FALSE;
            sp->ttis[0].tt_abbrind = 0;
            sp->ttis[1].tt_gmtoff = -dstoffset;
            sp->ttis[1].tt_isdst = TRUE;
            sp->ttis[1].tt_abbrind = stdlen + 1;
            sp->typecnt = 2;
        }
    } else {
        dstlen = 0;
        sp->typecnt = 1;        /* only standard time */
        sp->timecnt = 0;
        sp->ttis[0].tt_gmtoff = -stdoffset;
        sp->ttis[0].tt_isdst = 0;
        sp->ttis[0].tt_abbrind = 0;
    }
    sp->charcnt = stdlen + 1;
    if (dstlen != 0)
        sp->charcnt += dstlen + 1;
    if ((size_t) sp->charcnt > sizeof sp->chars)
        return -1;
    cp = sp->chars;
    (void) strncpy(cp, stdname, stdlen);
    cp += stdlen;
    *cp++ = '\0';
    if (dstlen != 0) {
        (void) strncpy(cp, dstname, dstlen);
        *(cp + dstlen) = '\0';
    }
    return 0;
}

static void
gmtload(sp)
struct state * const    sp;
{
    if (tzload(gmt, sp, TRUE) != 0)
        (void) tzparse(gmt, sp, TRUE);
}

static void
tzsetwall P((void))
{
    if (lcl_is_set < 0)
        return;
    lcl_is_set = -1;

#ifdef ALL_STATE
    if (lclptr == NULL) {
        lclptr = (struct state *) malloc(sizeof *lclptr);
        if (lclptr == NULL) {
            settzname();    /* all we can do */
            return;
        }
    }
#endif /* defined ALL_STATE */
    if (tzload((char *) NULL, lclptr, TRUE) != 0)
        gmtload(lclptr);
    settzname();
}

static void
tzset_locked P((void))
{
    register const char *   name = NULL;
    static char buf[PROP_VALUE_MAX];

    name = getenv("TZ");

#if 0
    // try the "persist.sys.timezone" system property first
    if (name == NULL && __system_property_get("persist.sys.timezone", buf) > 0)
        name = buf;
#endif

    if (name == NULL) {
        tzsetwall();
        return;
    }

    if (lcl_is_set > 0 && strcmp(lcl_TZname, name) == 0)
        return;
    lcl_is_set = strlen(name) < sizeof lcl_TZname;
    if (lcl_is_set)
        (void) strcpy(lcl_TZname, name);

#ifdef ALL_STATE
    if (lclptr == NULL) {
        lclptr = (struct state *) malloc(sizeof *lclptr);
        if (lclptr == NULL) {
            settzname();    /* all we can do */
            return;
        }
    }
#endif /* defined ALL_STATE */
    if (*name == '\0') {
        /*
        ** User wants it fast rather than right.
        */
        lclptr->leapcnt = 0;        /* so, we're off a little */
        lclptr->timecnt = 0;
        lclptr->typecnt = 0;
        lclptr->ttis[0].tt_isdst = 0;
        lclptr->ttis[0].tt_gmtoff = 0;
        lclptr->ttis[0].tt_abbrind = 0;
        (void) strcpy(lclptr->chars, gmt);
    } else if (tzload(name, lclptr, TRUE) != 0)
        if (name[0] == ':' || tzparse(name, lclptr, FALSE) != 0)
            (void) gmtload(lclptr);
    settzname();
}

void
tzset P((void))
{
    _tzLock();
    tzset_locked();
    _tzUnlock();
}

/*
** The easy way to behave "as if no library function calls" localtime
** is to not call it--so we drop its guts into "localsub", which can be
** freely called. (And no, the PANS doesn't require the above behavior--
** but it *is* desirable.)
**
** The unused offset argument is for the benefit of mktime variants.
*/

/*ARGSUSED*/
static struct tm *
localsub(timep, offset, tmp)
const time_t * const    timep;
const long      offset;
struct tm * const   tmp;
{
    register struct state *     sp;
    register const struct ttinfo *  ttisp;
    register int            i;
    register struct tm *        result;
    const time_t            t = *timep;

    sp = lclptr;
#ifdef ALL_STATE
    if (sp == NULL)
        return gmtsub(timep, offset, tmp);
#endif /* defined ALL_STATE */
    if ((sp->goback && t < sp->ats[0]) ||
        (sp->goahead && t > sp->ats[sp->timecnt - 1])) {
            time_t          newt = t;
            register time_t     seconds;
            register time_t     tcycles;
            register int_fast64_t   icycles;

            if (t < sp->ats[0])
                seconds = sp->ats[0] - t;
            else    seconds = t - sp->ats[sp->timecnt - 1];
            --seconds;
            tcycles = seconds / YEARSPERREPEAT / AVGSECSPERYEAR;
            ++tcycles;
            icycles = tcycles;
            if (tcycles - icycles >= 1 || icycles - tcycles >= 1)
                return NULL;
            seconds = icycles;
            seconds *= YEARSPERREPEAT;
            seconds *= AVGSECSPERYEAR;
            if (t < sp->ats[0])
                newt += seconds;
            else    newt -= seconds;
            if (newt < sp->ats[0] ||
                newt > sp->ats[sp->timecnt - 1])
                    return NULL;    /* "cannot happen" */
            result = localsub(&newt, offset, tmp);
            if (result == tmp) {
                register time_t newy;

                newy = tmp->tm_year;
                if (t < sp->ats[0])
                    newy -= icycles * YEARSPERREPEAT;
                else    newy += icycles * YEARSPERREPEAT;
                tmp->tm_year = newy;
                if (tmp->tm_year != newy)
                    return NULL;
            }
            return result;
    }
    if (sp->timecnt == 0 || t < sp->ats[0]) {
        i = 0;
        while (sp->ttis[i].tt_isdst)
            if (++i >= sp->typecnt) {
                i = 0;
                break;
            }
    } else {
        register int    lo = 1;
        register int    hi = sp->timecnt;

        while (lo < hi) {
            register int    mid = (lo + hi) >> 1;

            if (t < sp->ats[mid])
                hi = mid;
            else    lo = mid + 1;
        }
        i = (int) sp->types[lo - 1];
    }
    ttisp = &sp->ttis[i];
    /*
    ** To get (wrong) behavior that's compatible with System V Release 2.0
    ** you'd replace the statement below with
    **  t += ttisp->tt_gmtoff;
    **  timesub(&t, 0L, sp, tmp);
    */
    result = timesub(&t, ttisp->tt_gmtoff, sp, tmp);
    tmp->tm_isdst = ttisp->tt_isdst;
    tzname[tmp->tm_isdst] = &sp->chars[ttisp->tt_abbrind];
#ifdef TM_ZONE
    tmp->TM_ZONE = &sp->chars[ttisp->tt_abbrind];
#endif /* defined TM_ZONE */
    return result;
}

struct tm *
localtime(timep)
const time_t * const    timep;
{
    return localtime_r(timep, &tmGlobal);
}

/*
** Re-entrant version of localtime.
*/

struct tm *
localtime_r(timep, tmp)
const time_t * const    timep;
struct tm *     tmp;
{
    struct tm*  result;

    _tzLock();
    tzset_locked();
    result = localsub(timep, 0L, tmp);
    _tzUnlock();

    return result;
}

/*
** gmtsub is to gmtime as localsub is to localtime.
*/

static struct tm *
gmtsub(timep, offset, tmp)
const time_t * const    timep;
const long      offset;
struct tm * const   tmp;
{
    register struct tm *    result;

    if (!gmt_is_set) {
        gmt_is_set = TRUE;
#ifdef ALL_STATE
        gmtptr = (struct state *) malloc(sizeof *gmtptr);
        if (gmtptr != NULL)
#endif /* defined ALL_STATE */
            gmtload(gmtptr);
    }
    result = timesub(timep, offset, gmtptr, tmp);
#ifdef TM_ZONE
    /*
    ** Could get fancy here and deliver something such as
    ** "UTC+xxxx" or "UTC-xxxx" if offset is non-zero,
    ** but this is no time for a treasure hunt.
    */
    if (offset != 0)
        tmp->TM_ZONE = wildabbr;
    else {
#ifdef ALL_STATE
        if (gmtptr == NULL)
            tmp->TM_ZONE = gmt;
        else    tmp->TM_ZONE = gmtptr->chars;
#endif /* defined ALL_STATE */
#ifndef ALL_STATE
        tmp->TM_ZONE = gmtptr->chars;
#endif /* State Farm */
    }
#endif /* defined TM_ZONE */
    return result;
}

struct tm *
gmtime(timep)
const time_t * const    timep;
{
    return gmtime_r(timep, &tmGlobal);
}

/*
* Re-entrant version of gmtime.
*/

struct tm *
gmtime_r(timep, tmp)
const time_t * const    timep;
struct tm *     tmp;
{
    struct tm*  result;

    _tzLock();
    result = gmtsub(timep, 0L, tmp);
    _tzUnlock();

    return result;
}

#ifdef STD_INSPIRED

struct tm *
offtime(timep, offset)
const time_t * const    timep;
const long      offset;
{
    return gmtsub(timep, offset, &tmGlobal);
}

#endif /* defined STD_INSPIRED */

/*
** Return the number of leap years through the end of the given year
** where, to make the math easy, the answer for year zero is defined as zero.
*/

static int
leaps_thru_end_of(y)
register const int  y;
{
    return (y >= 0) ? (y / 4 - y / 100 + y / 400) :
        -(leaps_thru_end_of(-(y + 1)) + 1);
}

static struct tm *
timesub(timep, offset, sp, tmp)
const time_t * const            timep;
const long              offset;
register const struct state * const sp;
register struct tm * const      tmp;
{
    register const struct lsinfo *  lp;
    register time_t         tdays;
    register int            idays;  /* unsigned would be so 2003 */
    register long           rem;
    int             y;
    register const int *        ip;
    register long           corr;
    register int            hit;
    register int            i;

    corr = 0;
    hit = 0;
#ifdef ALL_STATE
    i = (sp == NULL) ? 0 : sp->leapcnt;
#endif /* defined ALL_STATE */
#ifndef ALL_STATE
    i = sp->leapcnt;
#endif /* State Farm */
    while (--i >= 0) {
        lp = &sp->lsis[i];
        if (*timep >= lp->ls_trans) {
            if (*timep == lp->ls_trans) {
                hit = ((i == 0 && lp->ls_corr > 0) ||
                    lp->ls_corr > sp->lsis[i - 1].ls_corr);
                if (hit)
                    while (i > 0 &&
                        sp->lsis[i].ls_trans ==
                        sp->lsis[i - 1].ls_trans + 1 &&
                        sp->lsis[i].ls_corr ==
                        sp->lsis[i - 1].ls_corr + 1) {
                            ++hit;
                            --i;
                    }
            }
            corr = lp->ls_corr;
            break;
        }
    }
    y = EPOCH_YEAR;
    tdays = *timep / SECSPERDAY;
    rem = *timep - tdays * SECSPERDAY;
    while (tdays < 0 || tdays >= year_lengths[isleap(y)]) {
        int     newy;
        register time_t tdelta;
        register int    idelta;
        register int    leapdays;

        tdelta = tdays / DAYSPERLYEAR;
        idelta = tdelta;
        if (tdelta - idelta >= 1 || idelta - tdelta >= 1)
            return NULL;
        if (idelta == 0)
            idelta = (tdays < 0) ? -1 : 1;
        newy = y;
        if (increment_overflow(&newy, idelta))
            return NULL;
        leapdays = leaps_thru_end_of(newy - 1) -
            leaps_thru_end_of(y - 1);
        tdays -= ((time_t) newy - y) * DAYSPERNYEAR;
        tdays -= leapdays;
        y = newy;
    }
    {
        register long   seconds;

        seconds = tdays * SECSPERDAY + 0.5;
        tdays = seconds / SECSPERDAY;
        rem += seconds - tdays * SECSPERDAY;
    }
    /*
    ** Given the range, we can now fearlessly cast...
    */
    idays = tdays;
    rem += offset - corr;
    while (rem < 0) {
        rem += SECSPERDAY;
        --idays;
    }
    while (rem >= SECSPERDAY) {
        rem -= SECSPERDAY;
        ++idays;
    }
    while (idays < 0) {
        if (increment_overflow(&y, -1))
            return NULL;
        idays += year_lengths[isleap(y)];
    }
    while (idays >= year_lengths[isleap(y)]) {
        idays -= year_lengths[isleap(y)];
        if (increment_overflow(&y, 1))
            return NULL;
    }
    tmp->tm_year = y;
    if (increment_overflow(&tmp->tm_year, -TM_YEAR_BASE))
        return NULL;
    tmp->tm_yday = idays;
    /*
    ** The "extra" mods below avoid overflow problems.
    */
    tmp->tm_wday = EPOCH_WDAY +
        ((y - EPOCH_YEAR) % DAYSPERWEEK) *
        (DAYSPERNYEAR % DAYSPERWEEK) +
        leaps_thru_end_of(y - 1) -
        leaps_thru_end_of(EPOCH_YEAR - 1) +
        idays;
    tmp->tm_wday %= DAYSPERWEEK;
    if (tmp->tm_wday < 0)
        tmp->tm_wday += DAYSPERWEEK;
    tmp->tm_hour = (int) (rem / SECSPERHOUR);
    rem %= SECSPERHOUR;
    tmp->tm_min = (int) (rem / SECSPERMIN);
    /*
    ** A positive leap second requires a special
    ** representation. This uses "... ??:59:60" et seq.
    */
    tmp->tm_sec = (int) (rem % SECSPERMIN) + hit;
    ip = mon_lengths[isleap(y)];
    for (tmp->tm_mon = 0; idays >= ip[tmp->tm_mon]; ++(tmp->tm_mon))
        idays -= ip[tmp->tm_mon];
    tmp->tm_mday = (int) (idays + 1);
    tmp->tm_isdst = 0;
#ifdef TM_GMTOFF
    tmp->TM_GMTOFF = offset;
#endif /* defined TM_GMTOFF */
    return tmp;
}

char *
ctime(timep)
const time_t * const    timep;
{
/*
** Section 4.12.3.2 of X3.159-1989 requires that
**  The ctime function converts the calendar time pointed to by timer
**  to local time in the form of a string. It is equivalent to
**      asctime(localtime(timer))
*/
    return asctime(localtime(timep));
}

char *
ctime_r(timep, buf)
const time_t * const    timep;
char *          buf;
{
    struct tm   mytm;

    return asctime_r(localtime_r(timep, &mytm), buf);
}

/*
** Adapted from code provided by Robert Elz, who writes:
**  The "best" way to do mktime I think is based on an idea of Bob
**  Kridle's (so its said...) from a long time ago.
**  It does a binary search of the time_t space. Since time_t's are
**  just 32 bits, its a max of 32 iterations (even at 64 bits it
**  would still be very reasonable).
*/

#ifndef WRONG
#define WRONG   (-1)
#endif /* !defined WRONG */

/*
** Simplified normalize logic courtesy Paul Eggert.
*/

static int
increment_overflow(number, delta)
int *   number;
int delta;
{
    unsigned  number0 = (unsigned)*number;
    unsigned  number1 = (unsigned)(number0 + delta);

    *number = (int)number1;

    if (delta >= 0) {
        return ((int)number1 < (int)number0);
    } else {
        return ((int)number1 > (int)number0);
    }
}

static int
long_increment_overflow(number, delta)
long *  number;
int delta;
{
    unsigned long  number0 = (unsigned long)*number;
    unsigned long  number1 = (unsigned long)(number0 + delta);

    *number = (long)number1;

    if (delta >= 0) {
        return ((long)number1 < (long)number0);
    } else {
        return ((long)number1 > (long)number0);
    }
}

static int
normalize_overflow(tensptr, unitsptr, base)
int * const tensptr;
int * const unitsptr;
const int   base;
{
    register int    tensdelta;

    tensdelta = (*unitsptr >= 0) ?
        (*unitsptr / base) :
        (-1 - (-1 - *unitsptr) / base);
    *unitsptr -= tensdelta * base;
    return increment_overflow(tensptr, tensdelta);
}

static int
long_normalize_overflow(tensptr, unitsptr, base)
long * const    tensptr;
int * const unitsptr;
const int   base;
{
    register int    tensdelta;

    tensdelta = (*unitsptr >= 0) ?
        (*unitsptr / base) :
        (-1 - (-1 - *unitsptr) / base);
    *unitsptr -= tensdelta * base;
    return long_increment_overflow(tensptr, tensdelta);
}

static int
tmcomp(atmp, btmp)
register const struct tm * const atmp;
register const struct tm * const btmp;
{
    register int    result;

    if ((result = (atmp->tm_year - btmp->tm_year)) == 0 &&
        (result = (atmp->tm_mon - btmp->tm_mon)) == 0 &&
        (result = (atmp->tm_mday - btmp->tm_mday)) == 0 &&
        (result = (atmp->tm_hour - btmp->tm_hour)) == 0 &&
        (result = (atmp->tm_min - btmp->tm_min)) == 0)
            result = atmp->tm_sec - btmp->tm_sec;
    return result;
}

static time_t
time2sub(tmp, funcp, offset, okayp, do_norm_secs)
struct tm * const   tmp;
struct tm * (* const    funcp) P((const time_t*, long, struct tm*));
const long      offset;
int * const     okayp;
const int       do_norm_secs;
{
    register const struct state *   sp;
    register int            dir;
    register int            i, j;
    register int            saved_seconds;
    register long           li;
    register time_t         lo;
    register time_t         hi;
    long                y;
    time_t              newt;
    time_t              t;
    struct tm           yourtm, mytm;

    *okayp = FALSE;
    yourtm = *tmp;
    if (do_norm_secs) {
        if (normalize_overflow(&yourtm.tm_min, &yourtm.tm_sec,
            SECSPERMIN))
                return WRONG;
    }
    if (normalize_overflow(&yourtm.tm_hour, &yourtm.tm_min, MINSPERHOUR))
        return WRONG;
    if (normalize_overflow(&yourtm.tm_mday, &yourtm.tm_hour, HOURSPERDAY))
        return WRONG;
    y = yourtm.tm_year;
    if (long_normalize_overflow(&y, &yourtm.tm_mon, MONSPERYEAR))
        return WRONG;
    /*
    ** Turn y into an actual year number for now.
    ** It is converted back to an offset from TM_YEAR_BASE later.
    */
    if (long_increment_overflow(&y, TM_YEAR_BASE))
        return WRONG;
    while (yourtm.tm_mday <= 0) {
        if (long_increment_overflow(&y, -1))
            return WRONG;
        li = y + (1 < yourtm.tm_mon);
        yourtm.tm_mday += year_lengths[isleap(li)];
    }
    while (yourtm.tm_mday > DAYSPERLYEAR) {
        li = y + (1 < yourtm.tm_mon);
        yourtm.tm_mday -= year_lengths[isleap(li)];
        if (long_increment_overflow(&y, 1))
            return WRONG;
    }
    for ( ; ; ) {
        i = mon_lengths[isleap(y)][yourtm.tm_mon];
        if (yourtm.tm_mday <= i)
            break;
        yourtm.tm_mday -= i;
        if (++yourtm.tm_mon >= MONSPERYEAR) {
            yourtm.tm_mon = 0;
            if (long_increment_overflow(&y, 1))
                return WRONG;
        }
    }
    if (long_increment_overflow(&y, -TM_YEAR_BASE))
        return WRONG;
    yourtm.tm_year = y;
    if (yourtm.tm_year != y)
        return WRONG;
    if (yourtm.tm_sec >= 0 && yourtm.tm_sec < SECSPERMIN)
        saved_seconds = 0;
    else if (y + TM_YEAR_BASE < EPOCH_YEAR) {
        /*
        ** We can't set tm_sec to 0, because that might push the
        ** time below the minimum representable time.
        ** Set tm_sec to 59 instead.
        ** This assumes that the minimum representable time is
        ** not in the same minute that a leap second was deleted from,
        ** which is a safer assumption than using 58 would be.
        */
        if (increment_overflow(&yourtm.tm_sec, 1 - SECSPERMIN))
            return WRONG;
        saved_seconds = yourtm.tm_sec;
        yourtm.tm_sec = SECSPERMIN - 1;
    } else {
        saved_seconds = yourtm.tm_sec;
        yourtm.tm_sec = 0;
    }
    /*
    ** Do a binary search (this works whatever time_t's type is).
    */
    if (!TYPE_SIGNED(time_t)) {
        lo = 0;
        hi = lo - 1;
    } else if (!TYPE_INTEGRAL(time_t)) {
        if (sizeof(time_t) > sizeof(float))
            hi = (time_t) DBL_MAX;
        else    hi = (time_t) FLT_MAX;
        lo = -hi;
    } else {
        lo = 1;
        for (i = 0; i < (int) TYPE_BIT(time_t) - 1; ++i)
            lo *= 2;
        hi = -(lo + 1);
    }
    for ( ; ; ) {
        t = lo / 2 + hi / 2;
        if (t < lo)
            t = lo;
        else if (t > hi)
            t = hi;
        if ((*funcp)(&t, offset, &mytm) == NULL) {
            /*
            ** Assume that t is too extreme to be represented in
            ** a struct tm; arrange things so that it is less
            ** extreme on the next pass.
            */
            dir = (t > 0) ? 1 : -1;
        } else  dir = tmcomp(&mytm, &yourtm);
        if (dir != 0) {
            if (t == lo) {
                if (t == TIME_T_MAX)
                    return WRONG;
                ++t;
                ++lo;
            } else if (t == hi) {
                if (t == TIME_T_MIN)
                    return WRONG;
                --t;
                --hi;
            }
            if (lo > hi)
                return WRONG;
            if (dir > 0)
                hi = t;
            else    lo = t;
            continue;
        }
        if (yourtm.tm_isdst < 0 || mytm.tm_isdst == yourtm.tm_isdst)
            break;
        /*
        ** Right time, wrong type.
        ** Hunt for right time, right type.
        ** It's okay to guess wrong since the guess
        ** gets checked.
        */
        /*
        ** The (void *) casts are the benefit of SunOS 3.3 on Sun 2's.
        */
        sp = (const struct state *)
            (((void *) funcp == (void *) localsub) ?
            lclptr : gmtptr);
#ifdef ALL_STATE
        if (sp == NULL)
            return WRONG;
#endif /* defined ALL_STATE */
        for (i = sp->typecnt - 1; i >= 0; --i) {
            if (sp->ttis[i].tt_isdst != yourtm.tm_isdst)
                continue;
            for (j = sp->typecnt - 1; j >= 0; --j) {
                if (sp->ttis[j].tt_isdst == yourtm.tm_isdst)
                    continue;
                newt = t + sp->ttis[j].tt_gmtoff -
                    sp->ttis[i].tt_gmtoff;
                if ((*funcp)(&newt, offset, &mytm) == NULL)
                    continue;
                if (tmcomp(&mytm, &yourtm) != 0)
                    continue;
                if (mytm.tm_isdst != yourtm.tm_isdst)
                    continue;
                /*
                ** We have a match.
                */
                t = newt;
                goto label;
            }
        }
        return WRONG;
    }
label:
    newt = t + saved_seconds;
    if ((newt < t) != (saved_seconds < 0))
        return WRONG;
    t = newt;
    if ((*funcp)(&t, offset, tmp))
        *okayp = TRUE;
    return t;
}

static time_t
time2(tmp, funcp, offset, okayp)
struct tm * const   tmp;
struct tm * (* const    funcp) P((const time_t*, long, struct tm*));
const long      offset;
int * const     okayp;
{
    time_t  t;

    /*
    ** First try without normalization of seconds
    ** (in case tm_sec contains a value associated with a leap second).
    ** If that fails, try with normalization of seconds.
    */
    t = time2sub(tmp, funcp, offset, okayp, FALSE);
    return *okayp ? t : time2sub(tmp, funcp, offset, okayp, TRUE);
}

static time_t
time1(tmp, funcp, offset)
struct tm * const   tmp;
struct tm * (* const    funcp) P((const time_t *, long, struct tm *));
const long      offset;
{
    register time_t         t;
    register const struct state *   sp;
    register int            samei, otheri;
    register int            sameind, otherind;
    register int            i;
    register int            nseen;
    int             seen[TZ_MAX_TYPES];
    int             types[TZ_MAX_TYPES];
    int             okay;

    if (tmp->tm_isdst > 1)
        tmp->tm_isdst = 1;
    t = time2(tmp, funcp, offset, &okay);
#ifdef PCTS
    /*
    ** PCTS code courtesy Grant Sullivan.
    */
    if (okay)
        return t;
    if (tmp->tm_isdst < 0)
        tmp->tm_isdst = 0;  /* reset to std and try again */
#endif /* defined PCTS */
#ifndef PCTS
    if (okay || tmp->tm_isdst < 0)
        return t;
#endif /* !defined PCTS */
    /*
    ** We're supposed to assume that somebody took a time of one type
    ** and did some math on it that yielded a "struct tm" that's bad.
    ** We try to divine the type they started from and adjust to the
    ** type they need.
    */
    /*
    ** The (void *) casts are the benefit of SunOS 3.3 on Sun 2's.
    */
    sp = (const struct state *) (((void *) funcp == (void *) localsub) ?
        lclptr : gmtptr);
#ifdef ALL_STATE
    if (sp == NULL)
        return WRONG;
#endif /* defined ALL_STATE */
    for (i = 0; i < sp->typecnt; ++i)
        seen[i] = FALSE;
    nseen = 0;
    for (i = sp->timecnt - 1; i >= 0; --i)
        if (!seen[sp->types[i]]) {
            seen[sp->types[i]] = TRUE;
            types[nseen++] = sp->types[i];
        }
    for (sameind = 0; sameind < nseen; ++sameind) {
        samei = types[sameind];
        if (sp->ttis[samei].tt_isdst != tmp->tm_isdst)
            continue;
        for (otherind = 0; otherind < nseen; ++otherind) {
            otheri = types[otherind];
            if (sp->ttis[otheri].tt_isdst == tmp->tm_isdst)
                continue;
            tmp->tm_sec += sp->ttis[otheri].tt_gmtoff -
                    sp->ttis[samei].tt_gmtoff;
            tmp->tm_isdst = !tmp->tm_isdst;
            t = time2(tmp, funcp, offset, &okay);
            if (okay)
                return t;
            tmp->tm_sec -= sp->ttis[otheri].tt_gmtoff -
                    sp->ttis[samei].tt_gmtoff;
            tmp->tm_isdst = !tmp->tm_isdst;
        }
    }
    return WRONG;
}

time_t
mktime(tmp)
struct tm * const   tmp;
{
    time_t  result;
    _tzLock();
    tzset_locked();
    result = time1(tmp, localsub, 0L);
    _tzUnlock();
    return result;
}

#ifdef STD_INSPIRED

time_t
timelocal(tmp)
struct tm * const   tmp;
{
    tmp->tm_isdst = -1; /* in case it wasn't initialized */
    return mktime(tmp);
}

time_t
timegm(tmp)
struct tm * const   tmp;
{
    time_t  result;

    tmp->tm_isdst = 0;
    _tzLock();
    result = time1(tmp, gmtsub, 0L);
    _tzUnlock();

    return result;
}

time_t
timeoff(tmp, offset)
struct tm * const   tmp;
const long      offset;
{
    time_t  result;

    tmp->tm_isdst = 0;
    _tzLock();
    result = time1(tmp, gmtsub, offset);
    _tzUnlock();

    return result;
}

#endif /* defined STD_INSPIRED */

#ifdef CMUCS

/*
** The following is supplied for compatibility with
** previous versions of the CMUCS runtime library.
*/

long
gtime(tmp)
struct tm * const   tmp;
{
    const time_t    t = mktime(tmp);

    if (t == WRONG)
        return -1;
    return t;
}

#endif /* defined CMUCS */

/*
** XXX--is the below the right way to conditionalize??
*/

#ifdef STD_INSPIRED

/*
** IEEE Std 1003.1-1988 (POSIX) legislates that 536457599
** shall correspond to "Wed Dec 31 23:59:59 UTC 1986", which
** is not the case if we are accounting for leap seconds.
** So, we provide the following conversion routines for use
** when exchanging timestamps with POSIX conforming systems.
*/

static long
leapcorr(timep)
time_t *    timep;
{
    register struct state *     sp;
    register struct lsinfo *    lp;
    register int            i;

    sp = lclptr;
    i = sp->leapcnt;
    while (--i >= 0) {
        lp = &sp->lsis[i];
        if (*timep >= lp->ls_trans)
            return lp->ls_corr;
    }
    return 0;
}

time_t
time2posix(t)
time_t  t;
{
    tzset();
    return t - leapcorr(&t);
}

time_t
posix2time(t)
time_t  t;
{
    time_t  x;
    time_t  y;

    tzset();
    /*
    ** For a positive leap second hit, the result
    ** is not unique. For a negative leap second
    ** hit, the corresponding time doesn't exist,
    ** so we return an adjacent second.
    */
    x = t + leapcorr(&t);
    y = x - leapcorr(&x);
    if (y < t) {
        do {
            x++;
            y = x - leapcorr(&x);
        } while (y < t);
        if (t != y)
            return x - 1;
    } else if (y > t) {
        do {
            --x;
            y = x - leapcorr(&x);
        } while (y > t);
        if (t != y)
            return x + 1;
    }
    return x;
}

#endif /* defined STD_INSPIRED */
