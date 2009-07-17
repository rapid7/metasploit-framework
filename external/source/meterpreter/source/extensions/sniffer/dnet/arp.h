/*
 * arp.h
 * 
 * Address Resolution Protocol.
 * RFC 826
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: arp.h,v 1.12 2003/03/16 17:39:17 dugsong Exp $
 */

#ifndef DNET_ARP_H
#define DNET_ARP_H

#define ARP_HDR_LEN	8	/* base ARP header length */
#define ARP_ETHIP_LEN	20	/* base ARP message length */

#ifndef __GNUC__
# define __attribute__(x)
# pragma pack(1)
#endif

/*
 * ARP header
 */
struct arp_hdr {
	uint16_t	ar_hrd;	/* format of hardware address */
	uint16_t	ar_pro;	/* format of protocol address */
	uint8_t		ar_hln;	/* length of hardware address (ETH_ADDR_LEN) */
	uint8_t		ar_pln;	/* length of protocol address (IP_ADDR_LEN) */
	uint16_t	ar_op;	/* operation */
};

/*
 * Hardware address format
 */
#define ARP_HRD_ETH 	0x0001	/* ethernet hardware */
#define ARP_HRD_IEEE802	0x0006	/* IEEE 802 hardware */

/*
 * Protocol address format
 */
#define ARP_PRO_IP	0x0800	/* IP protocol */

/*
 * ARP operation
 */
#define	ARP_OP_REQUEST		1	/* request to resolve ha given pa */
#define	ARP_OP_REPLY		2	/* response giving hardware address */
#define	ARP_OP_REVREQUEST	3	/* request to resolve pa given ha */
#define	ARP_OP_REVREPLY		4	/* response giving protocol address */

/*
 * Ethernet/IP ARP message
 */
struct arp_ethip {
	uint8_t		ar_sha[ETH_ADDR_LEN];	/* sender hardware address */
	uint8_t		ar_spa[IP_ADDR_LEN];	/* sender protocol address */
	uint8_t		ar_tha[ETH_ADDR_LEN];	/* target hardware address */
	uint8_t		ar_tpa[IP_ADDR_LEN];	/* target protocol address */
};

/*
 * ARP cache entry
 */
struct arp_entry {
	struct addr	arp_pa;			/* protocol address */
	struct addr	arp_ha;			/* hardware address */
};

#ifndef __GNUC__
# pragma pack()
#endif

#define arp_pack_hdr_ethip(hdr, op, sha, spa, tha, tpa) do {	\
	struct arp_hdr *pack_arp_p = (struct arp_hdr *)(hdr);	\
	struct arp_ethip *pack_ethip_p = (struct arp_ethip *)	\
		((uint8_t *)(hdr) + ARP_HDR_LEN);		\
	pack_arp_p->ar_hrd = htons(ARP_HRD_ETH);		\
	pack_arp_p->ar_pro = htons(ARP_PRO_IP);			\
	pack_arp_p->ar_hln = ETH_ADDR_LEN;			\
	pack_arp_p->ar_pln = IP_ADDR_LEN;			\
	pack_arp_p->ar_op = htons(op);				\
	memmove(pack_ethip_p->ar_sha, &(sha), ETH_ADDR_LEN);	\
	memmove(pack_ethip_p->ar_spa, &(spa), IP_ADDR_LEN);	\
	memmove(pack_ethip_p->ar_tha, &(tha), ETH_ADDR_LEN);	\
	memmove(pack_ethip_p->ar_tpa, &(tpa), IP_ADDR_LEN);	\
} while (0)

typedef struct arp_handle arp_t;

typedef int (*arp_handler)(const struct arp_entry *entry, void *arg);

__BEGIN_DECLS
arp_t	*arp_open(void);
int	 arp_add(arp_t *arp, const struct arp_entry *entry);
int	 arp_delete(arp_t *arp, const struct arp_entry *entry);
int	 arp_get(arp_t *arp, struct arp_entry *entry);
int	 arp_loop(arp_t *arp, arp_handler callback, void *arg);
arp_t	*arp_close(arp_t *arp);
__END_DECLS

#endif /* DNET_ARP_H */
