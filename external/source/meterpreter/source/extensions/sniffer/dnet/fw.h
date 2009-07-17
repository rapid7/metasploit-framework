/*
 * fw.h
 *
 * Network firewalling operations.
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: fw.h,v 1.13 2002/12/14 04:02:36 dugsong Exp $
 */

#ifndef DNET_FW_H
#define DNET_FW_H

struct fw_rule {
	char		fw_device[INTF_NAME_LEN]; /* interface name */
	uint8_t		fw_op;			  /* operation */
	uint8_t		fw_dir;			  /* direction */
	uint8_t		fw_proto;		  /* IP protocol */
	struct addr	fw_src;			  /* src address / net */
	struct addr	fw_dst;			  /* dst address / net */
	uint16_t	fw_sport[2];		  /* range / ICMP type */
	uint16_t	fw_dport[2];		  /* range / ICMP code */
};

#define FW_OP_ALLOW	1
#define FW_OP_BLOCK	2

#define FW_DIR_IN	1
#define FW_DIR_OUT	2

#define fw_pack_rule(rule, dev, op, dir, p, s, d, sp1, sp2, dp1, dp2)	\
do {									\
	strlcpy((rule)->fw_device, dev, sizeof((rule)->fw_device));	\
	(rule)->fw_op = op; (rule)->fw_dir = dir;			\
	(rule)->fw_proto = p;						\
	memmove(&(rule)->fw_src, &(s), sizeof((rule)->fw_src));		\
	memmove(&(rule)->fw_dst, &(d), sizeof((rule)->fw_dst));		\
	(rule)->fw_sport[0] = sp1; (rule)->fw_sport[1] = sp2;		\
	(rule)->fw_dport[0] = dp1; (rule)->fw_dport[1] = dp2;		\
} while (0)

typedef struct fw_handle fw_t;

typedef int (*fw_handler)(const struct fw_rule *rule, void *arg);

__BEGIN_DECLS
fw_t	*fw_open(void);
int	 fw_add(fw_t *f, const struct fw_rule *rule);
int	 fw_delete(fw_t *f, const struct fw_rule *rule);
int	 fw_loop(fw_t *f, fw_handler callback, void *arg);
fw_t	*fw_close(fw_t *f);
__END_DECLS

#endif /* DNET_FW_H */
