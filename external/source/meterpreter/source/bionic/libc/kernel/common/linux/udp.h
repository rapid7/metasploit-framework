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
#ifndef _LINUX_UDP_H
#define _LINUX_UDP_H

#include <linux/types.h>

struct udphdr {
 __u16 source;
 __u16 dest;
 __u16 len;
 __u16 check;
};

#define UDP_CORK 1  
#define UDP_ENCAP 100  

#define UDP_ENCAP_ESPINUDP_NON_IKE 1  
#define UDP_ENCAP_ESPINUDP 2  

#endif
