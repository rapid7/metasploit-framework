#ifndef _NETLINK_H_
#define _NETLINK_H_

#include <stdint.h>
#include <linux/netlink.h>

/* Netlink messages */

#define NETLINK_RECEIVE_BUFFER_SIZE 4096

struct nlmsghdr *get_batch_begin_nlmsg(void);
struct nlmsghdr *get_batch_end_nlmsg(void);

/* Netlink attributes */

#define U32_NLA_SIZE (sizeof(struct nlattr) + sizeof(uint32_t))
#define U64_NLA_SIZE (sizeof(struct nlattr) + sizeof(uint64_t))
#define S8_NLA_SIZE (sizeof(struct nlattr) + 8)
#define NLA_BIN_SIZE(x) (sizeof(struct nlattr) + x)
#define NLA_ATTR(attr) ((void *)attr + NLA_HDRLEN)

struct nlattr *set_nested_attr(struct nlattr *attr, uint16_t type, uint16_t data_len);
struct nlattr *set_u32_attr(struct nlattr *attr, uint16_t type, uint32_t value);
struct nlattr *set_u64_attr(struct nlattr *attr, uint16_t type, uint64_t value);
struct nlattr *set_str8_attr(struct nlattr *attr, uint16_t type, const char name[8]);
struct nlattr *set_binary_attr(struct nlattr *attr, uint16_t type, uint8_t *buffer, uint64_t buffer_size);

#endif /* _NETLINK_H_ */
