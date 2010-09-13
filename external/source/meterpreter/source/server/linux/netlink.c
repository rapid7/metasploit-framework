#include "common.h"

unsigned int seqno;

// PKS, pthread_self() = pointer to memory
#define NETLINKID() ((getpid() << 16) | gettid())

typedef int (*netlink_cb_t)(struct nlmsghdr *nh, void *data);

/*
 * Open a netlink socket. Maybe in the future we'll support another type.
 */

int netlink_socket(int type)
{
	int fd = -1;
	struct sockaddr_nl snl;

	memset(&snl, 0, sizeof(struct sockaddr_nl));

	dprintf("[%s] requesting netlink socket", __FUNCTION__);

	fd = socket(AF_NETLINK, SOCK_RAW, type);
	if(fd == -1) {
		dprintf("[%s] failed with %s", __FUNCTION__, strerror(errno));
		return -1;
	}

	snl.nl_family = AF_NETLINK;
	snl.nl_pid = NETLINKID();
		
	if(bind(fd, (void *)&snl, sizeof(struct sockaddr_nl)) == -1) {
		dprintf("[%s] Failed to bind to netlink socket: %s", __FUNCTION__, strerror(errno));
		close(fd);
		return -1;
	}

	dprintf("[%s] fd %d is a suitable netlink socket", __FUNCTION__, fd);

	return fd;
}

int netlink_request(int fd, int family, int type)
{
	unsigned char buf[sizeof(struct nlmsghdr) + sizeof(struct rtgenmsg)];
	struct nlmsghdr *nh;
	struct rtgenmsg *ng;

	struct sockaddr_nl snl;
	struct iovec iov;

	nh = (struct nlmsghdr *)(buf);
	ng = (struct rtgenmsg *)(buf + sizeof(struct nlmsghdr));
	
	dprintf("[%s] Setting up netlink request", __FUNCTION__);

	memset(&snl, 0, sizeof(struct sockaddr_nl));
	memset(buf, 0, sizeof(buf));

	snl.nl_family = AF_NETLINK;			// I keep auto typing AF_INET :~(

	nh->nlmsg_len = sizeof(buf);
	nh->nlmsg_type = type;
	
	// NLM_F_ROOT     Return the complete table instead of a single entry.

	// Create, remove or receive information about a network route.  These
	// messages contain an rtmsg structure with an optional sequence of
	// rtattr structures following.  For RTM_GETROUTE setting rtm_dst_len
	// and rtm_src_len to 0 means you get all entries for the specified
	// routing table.  For the other fields except rtm_table and
	// rtm_protocol 0 is the wildcard.

	nh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;

	// NLM_F_ACK       Request for an acknowledgment on success, maybe an idea.
	// would need to implement re-sending if it fails, etc.
	// for now we will assume it's reliable (even though the docs say it's not)

	nh->nlmsg_pid = NETLINKID();
	nh->nlmsg_seq = __atomic_inc(&seqno);

	ng->rtgen_family = family;
	
	dprintf("[%s] Sending request", __FUNCTION__);
	
	if(sendto(fd, buf, sizeof(buf), 0, (void *)(&snl), sizeof(struct sockaddr_nl)) == -1) {
		dprintf("[%s] Failed to send netlink request. Got %s", __FUNCTION__, strerror(errno));
		return -1;
	}

	dprintf("[%s] Request sent", __FUNCTION__);

	return seqno; // XXX, may wrap, etc. just use zero?

}

// man 7 netlink
int netlink_parse(int fd, int seq, netlink_cb_t callback, void *data)
{
	int len;
	int status;

	unsigned char buf[4096];
	struct sockaddr_nl snl;
	struct msghdr msg;
	struct iovec iov = { buf, sizeof(buf) };
	struct nlmsghdr *nh;

	memset(&snl, 0, sizeof(struct sockaddr_nl));
	snl.nl_family = AF_NETLINK;

	msg.msg_name = (void *)&snl;
	msg.msg_namelen = sizeof(struct sockaddr_nl);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;

	status = 0;

	do {
		len = recvmsg(fd, &msg, 0);
		dprintf("[%s] recvmsg returned %d", __FUNCTION__, len);

		if(len <= 0) {
			status = errno;
			dprintf("[%s] socket dead? bailing (%s)", __FUNCTION__, strerror(errno));
			break;
		}	

		if(msg.msg_flags & MSG_TRUNC) {
			dprintf("[%s] truncated message ? :(", __FUNCTION__);
			status = ERROR_NOT_SUPPORTED;
			break;
		}

		for(nh = (struct nlmsghdr *)(buf); NLMSG_OK(nh, len); nh = (struct nlmsghdr *) NLMSG_NEXT(nh, len)) {
			dprintf("[%s] buf = %p, nh = %p", __FUNCTION__, buf, nh);
			dprintf("[%s] nh->nlmsg_type = %d", __FUNCTION__, nh->nlmsg_type);

			if(nh->nlmsg_type == NLMSG_DONE) break;

			if(nh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *me = (struct nlmsgerr *) NLMSG_DATA (nh);
				dprintf("[%s] in NLMSG_ERROR handling.. me = %p", __FUNCTION__);
				dprintf("[%s] me->error = %d", __FUNCTION__, me->error);
				if(me->error) {
					dprintf("[%s] so, we have: nlmsg_len: %d, nlmsg_type: %d, nlmsg_flags: %d, nlmsg_seq: %d, nlmsg_pid: %d", 
						__FUNCTION__, me->msg.nlmsg_len, me->msg.nlmsg_type, me->msg.nlmsg_flags,
						me->msg.nlmsg_seq, me->msg.nlmsg_pid);

					if(me->msg.nlmsg_seq == seq) {
						dprintf("[%s] Hum. kernel doesn't like our message :~(", __FUNCTION__);
						status = ERROR_NOT_SUPPORTED;
						break;
					}

					dprintf("[%s] don't know how to handle this error at the moment. continuing", __FUNCTION__);
				}
				continue; // "yea, whatever"
			}

			// 

			dprintf("[%s] dispatching into callback", __FUNCTION__);

			status = callback(nh, data);

			if(status) {
				dprintf("[%s] callback returned non zero(%d) , stopping process", __FUNCTION__, status);
				break;
			}

		}

	} while(0);


	return status;
}


// man 7 rtnetlink
int netlink_parse_ipv4_routing_table(struct nlmsghdr *nh, void *data)
{
	struct ipv4_routing_table **table = (struct ipv4_routing_table **)(data);
	struct ipv4_routing_table *tmp;
	struct ipv4_route_entry *re;

	struct rtmsg *rm;
	struct rtattr *ra;
	int len;
	int newsize;

	__u32 dest, netmask, nexthop;
	__u32 *what;

	dest = netmask = nexthop = 0;

	if(nh->nlmsg_type != RTM_NEWROUTE) {
		dprintf("[%s] got %d instead of RTM_NEWROUTE (%d)", __FUNCTION__, nh->nlmsg_type, RTM_NEWROUTE);
		return 0;
	}

	rm = NLMSG_DATA(nh);

	if(rm->rtm_type != RTN_UNICAST) {
		dprintf("[%s] got %d instead of RTN_UNICAST (%d)", __FUNCTION__, rm->rtm_type, RTN_UNICAST);	
		return 0;
	}

	if(rm->rtm_family != AF_INET) {
		dprintf("[%s] dunno what on earth to do with a rtm_family of %d governor", __FUNCTION__, rm->rtm_family);
		return 0;
	}

	if(rm->rtm_flags & (RTM_F_CLONED | RTM_F_EQUALIZE)) {
		dprintf("[%s] cloned / equalized .. doesn't sound good. skipping for now", __FUNCTION__);
		return 0;
	}

	dprintf("[%s] nh->nlmsg_len: %d, NLMSG_LENGTH(sizeof(..)): %d", __FUNCTION__, nh->nlmsg_len, NLMSG_LENGTH(sizeof(struct rtmsg)));

	len = nh->nlmsg_len - NLMSG_LENGTH (sizeof(struct rtmsg));
	if(len <= 0) {
		dprintf("[%s] back to the drawing board it seems", __FUNCTION__);
		return 0;
	}

	dprintf("[%s] RTA_DST=%d, RTA_SRC=%d, RTA_GATEWAY=%d, RTA_PREFSRC=%d", __FUNCTION__, RTA_DST, RTA_SRC, RTA_GATEWAY, RTA_PREFSRC);		

	// okay, so.
	// 

	for(ra = (struct rtattr *) RTM_RTA(rm) ; RTA_OK(ra, len); ra = (struct rtattr *) RTA_NEXT(ra, len))
	{
		what = (__u32 *) RTA_DATA(ra);

		dprintf("[%s] ra @ %p, type = %d, length = %d, payload = %d, payload data = %08x", __FUNCTION__, ra, ra->rta_type, ra->rta_len, RTA_PAYLOAD(ra), *what);

		switch(ra->rta_type) {
			case RTA_DST:
				dest = *what;
				break;
			case RTA_GATEWAY:
				nexthop = *what;
				break;
		}
	}

	dprintf("[%s] and while you're here, rtm_dst_len = %d", __FUNCTION__, rm->rtm_dst_len);

	netmask = ((1 << rm->rtm_dst_len) - 1);
	
	newsize  = sizeof(struct ipv4_routing_table);
	newsize += ((*table)->entries + 1) * sizeof(struct ipv4_route_entry);

	tmp = realloc(*table, newsize);

	if(tmp == NULL) {
		return ENOMEM;
	}

	re = &(tmp->routes[tmp->entries]);

	re->dest = dest;
	re->netmask = netmask;
	re->nexthop = nexthop;

	dprintf("[%s] re->dest = %08x, re->netmask = %08x, re->nexthop = %08x", __FUNCTION__, re->dest, re->netmask, re->nexthop);
	tmp->entries++;

	*table = tmp;

	return 0;

}

int netlink_get_ipv4_routing_table(struct ipv4_routing_table **table)
{
	*table = NULL;

	int fd;
	int seq;
	int status;

	*table = calloc(sizeof(struct ipv4_routing_table), 1);
	if(*table == NULL) {
		return ENOMEM;
	}

	fd = netlink_socket(NETLINK_ROUTE);
	if(fd == -1) {
		dprintf("[%s] failed with netlink", __FUNCTION__);
		return ERROR_NOT_SUPPORTED;
	}

	seq = netlink_request(fd, AF_INET, RTM_GETROUTE);
	if(seq == -1) {
		dprintf("[%s] netlink_request failed", __FUNCTION__);
		close(fd);
		return ERROR_NOT_SUPPORTED;
	}

	status = netlink_parse(fd, seq, netlink_parse_ipv4_routing_table, table);

	close(fd);

	if(status != 0 && *table) {
		free(*table);
		*table = NULL;
	}
	
	return status;
}
