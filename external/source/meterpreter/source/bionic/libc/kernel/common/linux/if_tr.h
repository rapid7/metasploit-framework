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
#ifndef _LINUX_IF_TR_H
#define _LINUX_IF_TR_H

#include <asm/byteorder.h>  

#define TR_ALEN 6  
#define TR_HLEN (sizeof(struct trh_hdr)+sizeof(struct trllc))
#define AC 0x10
#define LLC_FRAME 0x40

#define EXTENDED_SAP 0xAA
#define UI_CMD 0x03

struct trh_hdr {
 __u8 ac;
 __u8 fc;
 __u8 daddr[TR_ALEN];
 __u8 saddr[TR_ALEN];
 __be16 rcf;
 __be16 rseg[8];
};

struct trllc {
 __u8 dsap;
 __u8 ssap;
 __u8 llc;
 __u8 protid[3];
 __be16 ethertype;
};

struct tr_statistics {
 unsigned long rx_packets;
 unsigned long tx_packets;
 unsigned long rx_bytes;
 unsigned long tx_bytes;
 unsigned long rx_errors;
 unsigned long tx_errors;
 unsigned long rx_dropped;
 unsigned long tx_dropped;
 unsigned long multicast;
 unsigned long transmit_collision;

 unsigned long line_errors;
 unsigned long internal_errors;
 unsigned long burst_errors;
 unsigned long A_C_errors;
 unsigned long abort_delimiters;
 unsigned long lost_frames;
 unsigned long recv_congest_count;
 unsigned long frame_copied_errors;
 unsigned long frequency_errors;
 unsigned long token_errors;
 unsigned long dummy1;
};

#define TR_RII 0x80
#define TR_RCF_DIR_BIT 0x80
#define TR_RCF_LEN_MASK 0x1f00
#define TR_RCF_BROADCAST 0x8000  
#define TR_RCF_LIMITED_BROADCAST 0xC000  
#define TR_RCF_FRAME2K 0x20
#define TR_RCF_BROADCAST_MASK 0xC000
#define TR_MAXRIFLEN 18

#endif
