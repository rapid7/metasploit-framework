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
#ifndef _X_TABLES_H
#define _X_TABLES_H

#define XT_FUNCTION_MAXNAMELEN 30
#define XT_TABLE_MAXNAMELEN 32

struct xt_entry_match
{
 union {
 struct {
 u_int16_t match_size;

 char name[XT_FUNCTION_MAXNAMELEN-1];

 u_int8_t revision;
 } user;
 struct {
 u_int16_t match_size;

 struct xt_match *match;
 } kernel;

 u_int16_t match_size;
 } u;

 unsigned char data[0];
};

struct xt_entry_target
{
 union {
 struct {
 u_int16_t target_size;

 char name[XT_FUNCTION_MAXNAMELEN-1];

 u_int8_t revision;
 } user;
 struct {
 u_int16_t target_size;

 struct xt_target *target;
 } kernel;

 u_int16_t target_size;
 } u;

 unsigned char data[0];
};

struct xt_standard_target
{
 struct xt_entry_target target;
 int verdict;
};

struct xt_get_revision
{
 char name[XT_FUNCTION_MAXNAMELEN-1];

 u_int8_t revision;
};

#define XT_CONTINUE 0xFFFFFFFF

#define XT_RETURN (-NF_REPEAT - 1)

struct _xt_align
{
 u_int8_t u8;
 u_int16_t u16;
 u_int32_t u32;
 u_int64_t u64;
};

#define XT_ALIGN(s) (((s) + (__alignof__(struct _xt_align)-1))   & ~(__alignof__(struct _xt_align)-1))

#define XT_STANDARD_TARGET ""

#define XT_ERROR_TARGET "ERROR"

#define XT_BASE_CTL 64  

#define XT_SO_SET_REPLACE (XT_BASE_CTL)
#define XT_SO_SET_ADD_COUNTERS (XT_BASE_CTL + 1)
#define XT_SO_SET_MAX XT_SO_SET_ADD_COUNTERS

#define XT_SO_GET_INFO (XT_BASE_CTL)
#define XT_SO_GET_ENTRIES (XT_BASE_CTL + 1)
#define XT_SO_GET_REVISION_MATCH (XT_BASE_CTL + 2)
#define XT_SO_GET_REVISION_TARGET (XT_BASE_CTL + 3)
#define XT_SO_GET_MAX XT_SO_GET_REVISION_TARGET

#define SET_COUNTER(c,b,p) do { (c).bcnt = (b); (c).pcnt = (p); } while(0)
#define ADD_COUNTER(c,b,p) do { (c).bcnt += (b); (c).pcnt += (p); } while(0)

struct xt_counters
{
 u_int64_t pcnt, bcnt;
};

struct xt_counters_info
{

 char name[XT_TABLE_MAXNAMELEN];

 unsigned int num_counters;

 struct xt_counters counters[0];
};

#define XT_INV_PROTO 0x40  

#endif
