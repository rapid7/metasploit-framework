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
#ifndef _IPT_HASHLIMIT_H
#define _IPT_HASHLIMIT_H

#define IPT_HASHLIMIT_SCALE 10000

struct ipt_hashlimit_htable;

#define IPT_HASHLIMIT_HASH_DIP 0x0001
#define IPT_HASHLIMIT_HASH_DPT 0x0002
#define IPT_HASHLIMIT_HASH_SIP 0x0004
#define IPT_HASHLIMIT_HASH_SPT 0x0008

struct hashlimit_cfg {
 u_int32_t mode;
 u_int32_t avg;
 u_int32_t burst;

 u_int32_t size;
 u_int32_t max;
 u_int32_t gc_interval;
 u_int32_t expire;
};

struct ipt_hashlimit_info {
 char name [IFNAMSIZ];
 struct hashlimit_cfg cfg;
 struct ipt_hashlimit_htable *hinfo;

 union {
 void *ptr;
 struct ipt_hashlimit_info *master;
 } u;
};
#endif
