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
#ifndef _LINUX_SKBUFF_H
#define _LINUX_SKBUFF_H

#include <linux/kernel.h>
#include <linux/compiler.h>
#include <linux/time.h>
#include <linux/cache.h>

#include <asm/atomic.h>
#include <asm/types.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/poll.h>
#include <linux/net.h>
#include <linux/textsearch.h>
#include <net/checksum.h>
#include <linux/dmaengine.h>

#define HAVE_ALLOC_SKB  
#define HAVE_ALIGNABLE_SKB  

#define CHECKSUM_NONE 0
#define CHECKSUM_HW 1
#define CHECKSUM_UNNECESSARY 2

#define SKB_DATA_ALIGN(X) (((X) + (SMP_CACHE_BYTES - 1)) &   ~(SMP_CACHE_BYTES - 1))
#define SKB_MAX_ORDER(X, ORDER) (((PAGE_SIZE << (ORDER)) - (X) -   sizeof(struct skb_shared_info)) &   ~(SMP_CACHE_BYTES - 1))
#define SKB_MAX_HEAD(X) (SKB_MAX_ORDER((X), 0))
#define SKB_MAX_ALLOC (SKB_MAX_ORDER(0, 2))

struct net_device;

struct sk_buff_head {

 struct sk_buff *next;
 struct sk_buff *prev;

 __u32 qlen;
 spinlock_t lock;
};

struct sk_buff;

#define MAX_SKB_FRAGS (65536/PAGE_SIZE + 2)

typedef struct skb_frag_struct skb_frag_t;

struct skb_frag_struct {
 struct page *page;
 __u16 page_offset;
 __u16 size;
};

struct skb_shared_info {
 atomic_t dataref;
 unsigned short nr_frags;
 unsigned short gso_size;

 unsigned short gso_segs;
 unsigned short gso_type;
 unsigned int ip6_frag_id;
 struct sk_buff *frag_list;
 skb_frag_t frags[MAX_SKB_FRAGS];
};

#define SKB_DATAREF_SHIFT 16
#define SKB_DATAREF_MASK ((1 << SKB_DATAREF_SHIFT) - 1)

struct skb_timeval {
 u32 off_sec;
 u32 off_usec;
};

enum {
 SKB_FCLONE_UNAVAILABLE,
 SKB_FCLONE_ORIG,
 SKB_FCLONE_CLONE,
};

enum {
 SKB_GSO_TCPV4 = 1 << 0,
 SKB_GSO_UDP = 1 << 1,

 SKB_GSO_DODGY = 1 << 2,

 SKB_GSO_TCP_ECN = 1 << 3,

 SKB_GSO_TCPV6 = 1 << 4,
};

struct sk_buff {

 struct sk_buff *next;
 struct sk_buff *prev;

 struct sock *sk;
 struct skb_timeval tstamp;
 struct net_device *dev;
 struct net_device *input_dev;

 union {
 struct tcphdr *th;
 struct udphdr *uh;
 struct icmphdr *icmph;
 struct igmphdr *igmph;
 struct iphdr *ipiph;
 struct ipv6hdr *ipv6h;
 unsigned char *raw;
 } h;

 union {
 struct iphdr *iph;
 struct ipv6hdr *ipv6h;
 struct arphdr *arph;
 unsigned char *raw;
 } nh;

 union {
 unsigned char *raw;
 } mac;

 struct dst_entry *dst;
 struct sec_path *sp;

 char cb[48];

 unsigned int len,
 data_len,
 mac_len,
 csum;
 __u32 priority;
 __u8 local_df:1,
 cloned:1,
 ip_summed:2,
 nohdr:1,
 nfctinfo:3;
 __u8 pkt_type:3,
 fclone:2,
 ipvs_property:1;
 __be16 protocol;

 void (*destructor)(struct sk_buff *skb);

 unsigned int truesize;
 atomic_t users;
 unsigned char *head,
 *data,
 *tail,
 *end;
};

#endif
