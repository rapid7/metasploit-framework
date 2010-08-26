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
#ifndef _LINUX_TCP_H
#define _LINUX_TCP_H

#include <linux/types.h>
#include <asm/byteorder.h>

struct tcphdr {
 __u16 source;
 __u16 dest;
 __u32 seq;
 __u32 ack_seq;
#ifdef __LITTLE_ENDIAN_BITFIELD
 __u16 res1:4,
 doff:4,
 fin:1,
 syn:1,
 rst:1,
 psh:1,
 ack:1,
 urg:1,
 ece:1,
 cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
 __u16 doff:4,
 res1:4,
 cwr:1,
 ece:1,
 urg:1,
 ack:1,
 psh:1,
 rst:1,
 syn:1,
 fin:1;
#else
#error "Adjust your <asm/byteorder.h> defines"
#endif
 __u16 window;
 __u16 check;
 __u16 urg_ptr;
};

union tcp_word_hdr {
 struct tcphdr hdr;
 __u32 words[5];
};

#define tcp_flag_word(tp) ( ((union tcp_word_hdr *)(tp))->words [3]) 

enum {
 TCP_FLAG_CWR = __constant_htonl(0x00800000),
 TCP_FLAG_ECE = __constant_htonl(0x00400000),
 TCP_FLAG_URG = __constant_htonl(0x00200000),
 TCP_FLAG_ACK = __constant_htonl(0x00100000),
 TCP_FLAG_PSH = __constant_htonl(0x00080000),
 TCP_FLAG_RST = __constant_htonl(0x00040000),
 TCP_FLAG_SYN = __constant_htonl(0x00020000),
 TCP_FLAG_FIN = __constant_htonl(0x00010000),
 TCP_RESERVED_BITS = __constant_htonl(0x0F000000),
 TCP_DATA_OFFSET = __constant_htonl(0xF0000000)
};

#define TCP_NODELAY 1  
#define TCP_MAXSEG 2  
#define TCP_CORK 3  
#define TCP_KEEPIDLE 4  
#define TCP_KEEPINTVL 5  
#define TCP_KEEPCNT 6  
#define TCP_SYNCNT 7  
#define TCP_LINGER2 8  
#define TCP_DEFER_ACCEPT 9  
#define TCP_WINDOW_CLAMP 10  
#define TCP_INFO 11  
#define TCP_QUICKACK 12  
#define TCP_CONGESTION 13  

#define TCPI_OPT_TIMESTAMPS 1
#define TCPI_OPT_SACK 2
#define TCPI_OPT_WSCALE 4
#define TCPI_OPT_ECN 8

enum tcp_ca_state
{
 TCP_CA_Open = 0,
#define TCPF_CA_Open (1<<TCP_CA_Open)
 TCP_CA_Disorder = 1,
#define TCPF_CA_Disorder (1<<TCP_CA_Disorder)
 TCP_CA_CWR = 2,
#define TCPF_CA_CWR (1<<TCP_CA_CWR)
 TCP_CA_Recovery = 3,
#define TCPF_CA_Recovery (1<<TCP_CA_Recovery)
 TCP_CA_Loss = 4
#define TCPF_CA_Loss (1<<TCP_CA_Loss)
};

struct tcp_info
{
 __u8 tcpi_state;
 __u8 tcpi_ca_state;
 __u8 tcpi_retransmits;
 __u8 tcpi_probes;
 __u8 tcpi_backoff;
 __u8 tcpi_options;
 __u8 tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;

 __u32 tcpi_rto;
 __u32 tcpi_ato;
 __u32 tcpi_snd_mss;
 __u32 tcpi_rcv_mss;

 __u32 tcpi_unacked;
 __u32 tcpi_sacked;
 __u32 tcpi_lost;
 __u32 tcpi_retrans;
 __u32 tcpi_fackets;

 __u32 tcpi_last_data_sent;
 __u32 tcpi_last_ack_sent;
 __u32 tcpi_last_data_recv;
 __u32 tcpi_last_ack_recv;

 __u32 tcpi_pmtu;
 __u32 tcpi_rcv_ssthresh;
 __u32 tcpi_rtt;
 __u32 tcpi_rttvar;
 __u32 tcpi_snd_ssthresh;
 __u32 tcpi_snd_cwnd;
 __u32 tcpi_advmss;
 __u32 tcpi_reordering;

 __u32 tcpi_rcv_rtt;
 __u32 tcpi_rcv_space;

 __u32 tcpi_total_retrans;
};

#endif
