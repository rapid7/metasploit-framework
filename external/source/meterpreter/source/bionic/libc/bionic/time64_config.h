/* Debugging
   TIME_64_DEBUG
   Define if you want debugging messages
*/
/* #define TIME_64_DEBUG */


/* INT_64_T
   A 64 bit integer type to use to store time and others.
   Must be defined.
*/
#define INT_64_T                long long


/* USE_TM64
   Should we use a 64 bit safe replacement for tm?  This will
   let you go past year 2 billion but the struct will be incompatible
   with tm.  Conversion functions will be provided.
*/
/* #define USE_TM64 */


/* Availability of system functions.

   HAS_GMTIME_R
   Define if your system has gmtime_r()

   HAS_LOCALTIME_R
   Define if your system has localtime_r()

   HAS_TIMEGM
   Define if your system has timegm(), a GNU extension.
*/
#define HAS_GMTIME_R
#define HAS_LOCALTIME_R
/*#define HAS_TIMEGM */


/* Details of non-standard tm struct elements.

   HAS_TM_TM_GMTOFF
   True if your tm struct has a "tm_gmtoff" element.
   A BSD extension.

   HAS_TM_TM_ZONE
   True if your tm struct has a "tm_zone" element.
   A BSD extension.
*/
#define HAS_TM_TM_GMTOFF
#define HAS_TM_TM_ZONE


/* USE_SYSTEM_LOCALTIME
   USE_SYSTEM_GMTIME
   Should we use the system functions if the time is inside their range?
   Your system localtime() is probably more accurate, but our gmtime() is
   fast and safe.
*/
#define USE_SYSTEM_LOCALTIME
/* #define USE_SYSTEM_GMTIME */


/* SYSTEM_LOCALTIME_MAX
   SYSTEM_LOCALTIME_MIN
   SYSTEM_GMTIME_MAX
   SYSTEM_GMTIME_MIN
   Maximum and minimum values your system's gmtime() and localtime()
   can handle.  We will use your system functions if the time falls
   inside these ranges.
*/
#define SYSTEM_LOCALTIME_MAX     2147483647
#define SYSTEM_LOCALTIME_MIN    -2147483647
#define SYSTEM_GMTIME_MAX        2147483647
#define SYSTEM_GMTIME_MIN       -2147483647

