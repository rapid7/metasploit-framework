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
#ifndef _IP_CONNTRACK_TUPLE_H
#define _IP_CONNTRACK_TUPLE_H

#include <linux/types.h>
#include <linux/netfilter/nf_conntrack_tuple_common.h>

union ip_conntrack_manip_proto
{

 u_int16_t all;

 struct {
 __be16 port;
 } tcp;
 struct {
 u_int16_t port;
 } udp;
 struct {
 u_int16_t id;
 } icmp;
 struct {
 u_int16_t port;
 } sctp;
 struct {
 __be16 key;
 } gre;
};

struct ip_conntrack_manip
{
 u_int32_t ip;
 union ip_conntrack_manip_proto u;
};

struct ip_conntrack_tuple
{
 struct ip_conntrack_manip src;

 struct {
 u_int32_t ip;
 union {

 u_int16_t all;

 struct {
 u_int16_t port;
 } tcp;
 struct {
 u_int16_t port;
 } udp;
 struct {
 u_int8_t type, code;
 } icmp;
 struct {
 u_int16_t port;
 } sctp;
 struct {
 __be16 key;
 } gre;
 } u;

 u_int8_t protonum;

 u_int8_t dir;
 } dst;
};

#define IP_CT_TUPLE_U_BLANK(tuple)   do {   (tuple)->src.u.all = 0;   (tuple)->dst.u.all = 0;   } while (0)

#endif
