/*
 * intf.c
 *
 * Network interface operations.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: intf.h,v 1.16 2004/01/13 07:41:09 dugsong Exp $
 */

#ifndef DNET_INTF_H
#define DNET_INTF_H

/*
 * Interface entry
 */
#define INTF_NAME_LEN	16

struct intf_entry {
	u_int		intf_len;		    /* length of entry */
	char		intf_name[INTF_NAME_LEN];   /* interface name */
	u_short		intf_type;		    /* interface type (r/o) */
	u_short		intf_flags;		    /* interface flags */
	u_int		intf_mtu;		    /* interface MTU */
	struct addr	intf_addr;		    /* interface address */
	struct addr	intf_dst_addr;		    /* point-to-point dst */
	struct addr	intf_link_addr;		    /* link-layer address */
	u_int		intf_alias_num;		    /* number of aliases */
	struct addr	intf_alias_addrs __flexarr; /* array of aliases */
};

/*
 * MIB-II interface types - http://www.iana.org/assignments/ianaiftype-mib
 */
#define INTF_TYPE_OTHER		1	/* other */
#define INTF_TYPE_ETH		6	/* Ethernet */
#define INTF_TYPE_TOKENRING	9	/* Token Ring */
#define INTF_TYPE_FDDI		15	/* FDDI */
#define INTF_TYPE_PPP		23	/* Point-to-Point Protocol */
#define INTF_TYPE_LOOPBACK	24	/* software loopback */
#define INTF_TYPE_SLIP		28	/* Serial Line Interface Protocol */
#define INTF_TYPE_TUN		53	/* proprietary virtual/internal */

/*
 * Interface flags
 */
#define INTF_FLAG_UP		0x01	/* enable interface */
#define INTF_FLAG_LOOPBACK	0x02	/* is a loopback net (r/o) */
#define INTF_FLAG_POINTOPOINT	0x04	/* point-to-point link (r/o) */
#define INTF_FLAG_NOARP		0x08	/* disable ARP */
#define INTF_FLAG_BROADCAST	0x10	/* supports broadcast (r/o) */
#define INTF_FLAG_MULTICAST	0x20	/* supports multicast (r/o) */

typedef struct intf_handle intf_t;

typedef int (*intf_handler)(const struct intf_entry *entry, void *arg);

__BEGIN_DECLS
intf_t	*intf_open(void);
int	 intf_get(intf_t *i, struct intf_entry *entry);
int	 intf_get_src(intf_t *i, struct intf_entry *entry, struct addr *src);
int	 intf_get_dst(intf_t *i, struct intf_entry *entry, struct addr *dst);
int	 intf_set(intf_t *i, const struct intf_entry *entry);
int	 intf_loop(intf_t *i, intf_handler callback, void *arg);
intf_t	*intf_close(intf_t *i);
__END_DECLS

#endif /* DNET_INTF_H */
