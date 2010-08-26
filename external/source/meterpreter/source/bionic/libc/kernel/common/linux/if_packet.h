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
#ifndef __LINUX_IF_PACKET_H
#define __LINUX_IF_PACKET_H

struct sockaddr_pkt
{
 unsigned short spkt_family;
 unsigned char spkt_device[14];
 unsigned short spkt_protocol;
};

struct sockaddr_ll
{
 unsigned short sll_family;
 unsigned short sll_protocol;
 int sll_ifindex;
 unsigned short sll_hatype;
 unsigned char sll_pkttype;
 unsigned char sll_halen;
 unsigned char sll_addr[8];
};

#define PACKET_HOST 0  
#define PACKET_BROADCAST 1  
#define PACKET_MULTICAST 2  
#define PACKET_OTHERHOST 3  
#define PACKET_OUTGOING 4  

#define PACKET_LOOPBACK 5  
#define PACKET_FASTROUTE 6  

#define PACKET_ADD_MEMBERSHIP 1
#define PACKET_DROP_MEMBERSHIP 2
#define PACKET_RECV_OUTPUT 3

#define PACKET_RX_RING 5
#define PACKET_STATISTICS 6
#define PACKET_COPY_THRESH 7

struct tpacket_stats
{
 unsigned int tp_packets;
 unsigned int tp_drops;
};

struct tpacket_hdr
{
 unsigned long tp_status;
#define TP_STATUS_KERNEL 0
#define TP_STATUS_USER 1
#define TP_STATUS_COPY 2
#define TP_STATUS_LOSING 4
#define TP_STATUS_CSUMNOTREADY 8
 unsigned int tp_len;
 unsigned int tp_snaplen;
 unsigned short tp_mac;
 unsigned short tp_net;
 unsigned int tp_sec;
 unsigned int tp_usec;
};

#define TPACKET_ALIGNMENT 16
#define TPACKET_ALIGN(x) (((x)+TPACKET_ALIGNMENT-1)&~(TPACKET_ALIGNMENT-1))
#define TPACKET_HDRLEN (TPACKET_ALIGN(sizeof(struct tpacket_hdr)) + sizeof(struct sockaddr_ll))

struct tpacket_req
{
 unsigned int tp_block_size;
 unsigned int tp_block_nr;
 unsigned int tp_frame_size;
 unsigned int tp_frame_nr;
};

struct packet_mreq
{
 int mr_ifindex;
 unsigned short mr_type;
 unsigned short mr_alen;
 unsigned char mr_address[8];
};

#define PACKET_MR_MULTICAST 0
#define PACKET_MR_PROMISC 1
#define PACKET_MR_ALLMULTI 2

#endif
