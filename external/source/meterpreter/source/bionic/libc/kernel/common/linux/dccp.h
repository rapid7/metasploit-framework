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
#ifndef _LINUX_DCCP_H
#define _LINUX_DCCP_H

#include <linux/types.h>
#include <asm/byteorder.h>

struct dccp_hdr {
 __be16 dccph_sport,
 dccph_dport;
 __u8 dccph_doff;
#ifdef __LITTLE_ENDIAN_BITFIELD
 __u8 dccph_cscov:4,
 dccph_ccval:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
 __u8 dccph_ccval:4,
 dccph_cscov:4;
#else
#error "Adjust your <asm/byteorder.h> defines"
#endif
 __u16 dccph_checksum;
#ifdef __LITTLE_ENDIAN_BITFIELD
 __u8 dccph_x:1,
 dccph_type:4,
 dccph_reserved:3;
#elif defined(__BIG_ENDIAN_BITFIELD)
 __u8 dccph_reserved:3,
 dccph_type:4,
 dccph_x:1;
#else
#error "Adjust your <asm/byteorder.h> defines"
#endif
 __u8 dccph_seq2;
 __be16 dccph_seq;
};

struct dccp_hdr_ext {
 __be32 dccph_seq_low;
};

struct dccp_hdr_request {
 __be32 dccph_req_service;
};

struct dccp_hdr_ack_bits {
 __be16 dccph_reserved1;
 __be16 dccph_ack_nr_high;
 __be32 dccph_ack_nr_low;
};

struct dccp_hdr_response {
 struct dccp_hdr_ack_bits dccph_resp_ack;
 __be32 dccph_resp_service;
};

struct dccp_hdr_reset {
 struct dccp_hdr_ack_bits dccph_reset_ack;
 __u8 dccph_reset_code,
 dccph_reset_data[3];
};

enum dccp_pkt_type {
 DCCP_PKT_REQUEST = 0,
 DCCP_PKT_RESPONSE,
 DCCP_PKT_DATA,
 DCCP_PKT_ACK,
 DCCP_PKT_DATAACK,
 DCCP_PKT_CLOSEREQ,
 DCCP_PKT_CLOSE,
 DCCP_PKT_RESET,
 DCCP_PKT_SYNC,
 DCCP_PKT_SYNCACK,
 DCCP_PKT_INVALID,
};

#define DCCP_NR_PKT_TYPES DCCP_PKT_INVALID

enum {
 DCCPO_PADDING = 0,
 DCCPO_MANDATORY = 1,
 DCCPO_MIN_RESERVED = 3,
 DCCPO_MAX_RESERVED = 31,
 DCCPO_CHANGE_L = 32,
 DCCPO_CONFIRM_L = 33,
 DCCPO_CHANGE_R = 34,
 DCCPO_CONFIRM_R = 35,
 DCCPO_NDP_COUNT = 37,
 DCCPO_ACK_VECTOR_0 = 38,
 DCCPO_ACK_VECTOR_1 = 39,
 DCCPO_TIMESTAMP = 41,
 DCCPO_TIMESTAMP_ECHO = 42,
 DCCPO_ELAPSED_TIME = 43,
 DCCPO_MAX = 45,
 DCCPO_MIN_CCID_SPECIFIC = 128,
 DCCPO_MAX_CCID_SPECIFIC = 255,
};

enum {
 DCCPF_RESERVED = 0,
 DCCPF_CCID = 1,
 DCCPF_SEQUENCE_WINDOW = 3,
 DCCPF_ACK_RATIO = 5,
 DCCPF_SEND_ACK_VECTOR = 6,
 DCCPF_SEND_NDP_COUNT = 7,

 DCCPF_MIN_CCID_SPECIFIC = 128,
 DCCPF_MAX_CCID_SPECIFIC = 255,
};

struct dccp_so_feat {
 __u8 dccpsf_feat;
 __u8 *dccpsf_val;
 __u8 dccpsf_len;
};

#define DCCP_SOCKOPT_PACKET_SIZE 1
#define DCCP_SOCKOPT_SERVICE 2
#define DCCP_SOCKOPT_CHANGE_L 3
#define DCCP_SOCKOPT_CHANGE_R 4
#define DCCP_SOCKOPT_CCID_RX_INFO 128
#define DCCP_SOCKOPT_CCID_TX_INFO 192

#define DCCP_SERVICE_LIST_MAX_LEN 32

#endif
