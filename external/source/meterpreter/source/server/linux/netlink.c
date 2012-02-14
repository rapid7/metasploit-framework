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
	//snl.nl_pid = NETLINKID();
	// some systems require pid to 0
	snl.nl_pid = 0;
		
	if(bind(fd, (void *)&snl, sizeof(struct sockaddr_nl)) == -1) {
		dprintf("[%s] Failed to bind to netlink socket: %s", __FUNCTION__, strerror(errno));
		close(fd);
		return -1;
	}
	// let's add some random to seqno
	seqno = time(NULL);
	dprintf("[%s] fd %d is a suitable netlink socket", __FUNCTION__, fd);

	return fd;
}

int netlink_request(int fd, int family, int type)
{
	// send at least 16 bytes of data, some old kernels want it
	unsigned char buf[sizeof(struct nlmsghdr) + sizeof(struct rtgenmsg)+15];
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

	nh->nlmsg_len =  NLMSG_LENGTH(sizeof(buf) - sizeof(struct nlmsghdr));
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

	//nh->nlmsg_pid = NETLINKID();
	// some systems require pid to 0
	nh->nlmsg_pid =0;
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
    int end = 0;
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

			if(nh->nlmsg_type == NLMSG_DONE) {
                end = 1;
                break;
            }

			if(nh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *me = (struct nlmsgerr *) NLMSG_DATA (nh);
				dprintf("[%s] in NLMSG_ERROR handling.. me = %p", __FUNCTION__, me);
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

	} while(!end);


	return status;
}


// man 7 rtnetlink
int netlink_parse_routing_table(struct nlmsghdr *nh, void *data)
{
	struct routing_table * rt_table = ( struct routing_table *) data;
	struct ipv4_routing_table **table_v4 = rt_table->table_ipv4;
	struct ipv6_routing_table **table_v6 = rt_table->table_ipv6;
	struct ipv4_routing_table *tmp;
	struct ipv6_routing_table *tmp6;
	struct ipv4_route_entry *re;
	struct ipv6_route_entry *re6;

	struct rtmsg *rm;
	struct rtattr *ra;
	int len;
	int newsize;
	unsigned char is_ipv6;
	unsigned char int_name[IFNAMSIZ+1];
	uint32_t interface_index, metric;

	__u32 dest, netmask, nexthop;
	__u32 *what;

	__u128 dest6, netmask6, nexthop6;
	unsigned char *what6;

	dest = netmask = nexthop = metric = 0;
	memset(&dest6, 0, sizeof(__u128));
	memset(&netmask6, 0, sizeof(__u128));
	memset(&nexthop6, 0, sizeof(__u128));

	memset(int_name, 0, IFNAMSIZ+1);

	if(nh->nlmsg_type != RTM_NEWROUTE) {
		dprintf("[%s] got %d instead of RTM_NEWROUTE (%d)", __FUNCTION__, nh->nlmsg_type, RTM_NEWROUTE);
		return 0;
	}

	rm = NLMSG_DATA(nh);

	if(rm->rtm_type != RTN_UNICAST ) {
		dprintf("[%s] got %d instead of RTN_UNICAST (%d)", __FUNCTION__, rm->rtm_type, RTN_UNICAST);	
		return 0;
	}

	if(rm->rtm_family != AF_INET && rm->rtm_family != AF_INET6) {
		dprintf("[%s] dunno what on earth to do with a rtm_family of %d governor", __FUNCTION__, rm->rtm_family);
		return 0;
	}

	if(rm->rtm_flags & (RTM_F_CLONED | RTM_F_EQUALIZE)) {
		dprintf("[%s] cloned / equalized .. doesn't sound good. skipping for now", __FUNCTION__);
		return 0;
	}

    if (rm->rtm_family == AF_INET)
        is_ipv6 = 0;
    else
        is_ipv6 = 1;

	dprintf("[%s] nh->nlmsg_len: %d, NLMSG_LENGTH(sizeof(..)): %d, is_ipv6 : %d", __FUNCTION__, nh->nlmsg_len, NLMSG_LENGTH(sizeof(struct rtmsg)),is_ipv6);

	len = nh->nlmsg_len - NLMSG_LENGTH (sizeof(struct rtmsg));
	if(len <= 0) {
		dprintf("[%s] back to the drawing board it seems", __FUNCTION__);
		return 0;
	}

	dprintf("[%s] RTA_DST=%d, RTA_SRC=%d, RTA_GATEWAY=%d, RTA_PREFSRC=%d, RTA_OIF=%d, RTA_PRIORITY=%d", __FUNCTION__, RTA_DST, RTA_SRC, RTA_GATEWAY, RTA_PREFSRC,RTA_OIF, RTA_PRIORITY);		

	// okay, so.
	// 

	for(ra = (struct rtattr *) RTM_RTA(rm) ; RTA_OK(ra, len); ra = (struct rtattr *) RTA_NEXT(ra, len))
	{
        if (is_ipv6) {
            what6 = (unsigned char *) RTA_DATA(ra);
		    dprintf("[%s] ra @ %p, type = %d, length = %d, payload = %d, payload data = %08x %08x %08x %08x", __FUNCTION__, ra, ra->rta_type, ra->rta_len, RTA_PAYLOAD(ra), *(__u32 *)what6, *(__u32 *)(what6+4), *(__u32 *)(what6+8), *(__u32 *)(what6+12));
        }
        else {
		    what = (__u32 *) RTA_DATA(ra);
		    dprintf("[%s] ra @ %p, type = %d, length = %d, payload = %d, payload data = %08x", __FUNCTION__, ra, ra->rta_type, ra->rta_len, RTA_PAYLOAD(ra), *what);
        }

		switch(ra->rta_type) {
			case RTA_DST:
				if (is_ipv6)
					memcpy(&dest6,what6, sizeof(__u128));
				else
					dest = *what;
				break;
			case RTA_GATEWAY:
				if (is_ipv6)
					memcpy(&nexthop6,what6, sizeof(__u128));
				else
					nexthop = *what;
				break;
			case RTA_OIF:
				interface_index = *(uint32_t *)RTA_DATA(ra);
				if_indextoname(interface_index, int_name);
				break;
            case RTA_PRIORITY:
				// metric is a uint16_t but we must transmit 32bits integers
				metric = (*(uint32_t *)RTA_DATA(ra))&0x0000ffff;
				break;
		}
	}

	dprintf("[%s] and while you're here, rtm_dst_len = %d", __FUNCTION__, rm->rtm_dst_len);

    if (is_ipv6) {
        // if netmask is FFFFFFFF FFFFFFFF 00000000 00000000 (/64), netmask6.a1 and netmask6.a2 == 0xffffffff, and nestmask6.a3 and .a4 == 0
        // netmask6 is set to 0 at the beginning of the function, no need to reset the values to 0 if it is needed
        // XXX really ugly, but works
        if (rm->rtm_dst_len >= 96) {
            netmask6.a4 = (1 << (rm->rtm_dst_len-96))-1;
            netmask6.a1 = netmask6.a2 = netmask6.a3 =  0xffffffff;
        }
        else if (rm->rtm_dst_len >= 64) {
            netmask6.a3 = (1 << (rm->rtm_dst_len-64))-1;
            netmask6.a1 = netmask6.a2 =  0xffffffff;
        }
        else if (rm->rtm_dst_len >= 32) {
            netmask6.a2 = (1 << (rm->rtm_dst_len-32))-1;
            netmask6.a1 =  0xffffffff;
        }
        else
           netmask6.a1 = (1 << rm->rtm_dst_len)-1;
    }
    else
	    netmask = ((1 << rm->rtm_dst_len) - 1);
	

    if (is_ipv6) {
        newsize  = sizeof(struct ipv6_routing_table);
	    newsize += ((*table_v6)->entries + 1) * sizeof(struct ipv6_route_entry);

	    tmp6 = realloc(*table_v6, newsize);

        if(tmp6 == NULL) {
		    return ENOMEM;
	    }

	    re6 = &(tmp6->routes[tmp6->entries]);

	    memcpy(&re6->dest6, &dest6, sizeof(__u128));
	    memcpy(&re6->netmask6, &netmask6, sizeof(__u128));
	    memcpy(&re6->nexthop6, &nexthop6, sizeof(__u128));
   
        strncpy(re6->interface, int_name, IFNAMSIZ);
        // numbers are transmitted in network byte order
		re6->metric = htonl(metric);
		dprintf("[%s] re6->dest6 = %08x %08x %08x %08x, re6->netmask6 = %08x %08x %08x %08x, re6->nexthop6 = %08x %08x %08x %08x, interface = %s, metric = %d", __FUNCTION__, 
		re6->dest6.a1,re6->dest6.a2,re6->dest6.a3,re6->dest6.a4,
		re6->netmask6.a1,re6->netmask6.a2,re6->netmask6.a3,re6->netmask6.a4,
		re6->nexthop6.a1,re6->nexthop6.a2,re6->nexthop6.a3,re6->nexthop6.a4,
		re6->interface,ntohl(re6->metric));
		tmp6->entries++;

		*table_v6 = tmp6;
    }
    else {
	    newsize  = sizeof(struct ipv4_routing_table);
	    newsize += ((*table_v4)->entries + 1) * sizeof(struct ipv4_route_entry);

	    tmp = realloc(*table_v4, newsize);

	    if(tmp == NULL) {
		    return ENOMEM;
	    }

	    re = &(tmp->routes[tmp->entries]);

	    re->dest = dest;
	    re->netmask = netmask;
	    re->nexthop = nexthop;
        strncpy(re->interface, int_name, IFNAMSIZ);
        // numbers are transmitted in network byte order
        re->metric = htonl(metric);

	    dprintf("[%s] re->dest = %08x, re->netmask = %08x, re->nexthop = %08x, interface = %s, metric = %d", __FUNCTION__, re->dest, re->netmask, re->nexthop,re->interface,ntohl(re->metric));
	    tmp->entries++;

	    *table_v4 = tmp;
    }

	return 0;

}

int netlink_get_routing_table(struct ipv4_routing_table **table_ipv4, struct ipv6_routing_table **table_ipv6)
{


	int fd;
	int seq;
	int status;
    struct routing_table table;
    
    *table_ipv4 = NULL;
    *table_ipv6 = NULL;
    table.table_ipv4 = table_ipv4;
    table.table_ipv6 = table_ipv6;


	*table_ipv4 = calloc(sizeof(struct ipv4_routing_table), 1);
	*table_ipv6 = calloc(sizeof(struct ipv6_routing_table), 1);
	if(*table_ipv4 == NULL) {
		return ENOMEM;
	}
	if(*table_ipv6 == NULL) {
        free(*table_ipv4);
		return ENOMEM;
	}

	fd = netlink_socket(NETLINK_ROUTE);
	if(fd == -1) {
		dprintf("[%s] failed with netlink", __FUNCTION__);
		return ERROR_NOT_SUPPORTED;
	}

	seq = netlink_request(fd, AF_PACKET, RTM_GETROUTE);
	if(seq == -1) {
		dprintf("[%s] netlink_request RTM_GETROUTE failed", __FUNCTION__);
		close(fd);
		return ERROR_NOT_SUPPORTED;
	}

	status = netlink_parse(fd, seq, netlink_parse_routing_table, &table);

	close(fd);

	if(status != 0) {
        if (*table_ipv4)
		    free(*table_ipv4);
        if (*table_ipv6)
		    free(*table_ipv6);
		*table_ipv4 = NULL;
		*table_ipv6 = NULL;
	}
	
	return status;
}

void flags_to_string(uint32_t flags, unsigned char * buffer, uint32_t buffer_len)
{
	if ((flags & IFF_UP) == IFF_UP)
		strncat(buffer, "UP ",buffer_len - strlen(buffer));
	if ((flags & IFF_BROADCAST) == IFF_BROADCAST)
		strncat(buffer, "BROADCAST ",buffer_len - strlen(buffer));
	if ((flags & IFF_LOOPBACK) == IFF_LOOPBACK)
		strncat(buffer, "LOOPBACK ",buffer_len - strlen(buffer));
	if ((flags & IFF_POINTOPOINT) == IFF_POINTOPOINT)
		strncat(buffer, "POINTOPOINT ",buffer_len - strlen(buffer));
	if ((flags & IFF_RUNNING) == IFF_RUNNING)
		strncat(buffer, "RUNNING ",buffer_len - strlen(buffer));
	if ((flags & IFF_PROMISC) == IFF_PROMISC)
		strncat(buffer, "PROMISC ",buffer_len - strlen(buffer));
	if ((flags & IFF_MULTICAST) == IFF_MULTICAST)
		strncat(buffer, "MULTICAST ",buffer_len - strlen(buffer));
}

int netlink_parse_interface_link(struct nlmsghdr *nh, void *data)
{
	struct ifaces_list ** iface_list = ( struct ifaces_list **) data;
	struct ifaces_list  *tmp;
	struct iface_entry iface_tmp;
	struct iface_entry * iff;

	struct ifinfomsg *iface;
	struct rtattr *attribute;
	uint32_t len;
	uint32_t newsize;

	iface = NLMSG_DATA(nh);
	len = nh->nlmsg_len - NLMSG_LENGTH(sizeof(*iface));
	memset(&iface_tmp, 0, sizeof(iface_tmp));

	// index of the interface
	iface_tmp.index = iface->ifi_index;
	//flags of the interface, string version
	flags_to_string(iface->ifi_flags, iface_tmp.flags, FLAGS_LEN);

	for (attribute = IFLA_RTA(iface); RTA_OK(attribute, len); attribute = RTA_NEXT(attribute, len))
	{

		switch(attribute->rta_type)
		{
			case IFLA_IFNAME:
				strncpy(iface_tmp.name, (unsigned char *) RTA_DATA(attribute), IFNAMSIZ);
				break;
			case IFLA_ADDRESS:
				memcpy(iface_tmp.hwaddr, (unsigned char *) RTA_DATA(attribute), 6);
				break;
			case IFLA_MTU:
				iface_tmp.mtu = *(uint32_t *)RTA_DATA(attribute);
				break;
			default:
				break;
	    }
    }

	newsize  = sizeof(struct ifaces_list);
	newsize += ((*iface_list)->entries + 1) * sizeof(struct iface_entry);

	tmp = realloc(*iface_list, newsize);

	if(tmp == NULL) {
		return ENOMEM;
	}

	iff = &(tmp->ifaces[tmp->entries]);
	memset(iff, 0, sizeof(struct iface_entry));

	iff->index = iface_tmp.index;
	strncpy(iff->name, iface_tmp.name, IFNAMSIZ);
	memcpy(iff->hwaddr, iface_tmp.hwaddr, 6);
	strncpy(iff->flags, iface_tmp.flags, FLAGS_LEN);
	// numbers are transmitted in network byte order
	iff->mtu = htonl(iface_tmp.mtu);

	dprintf("[%s] iff->index = %d, iff->name = %s, iff->hwaddr = %02x:%02x:%02x:%02x:%02x:%02x, iff->mtu = %d, iff->flags = %s, real_flags = 0x%08x", __FUNCTION__, iff->index, iff->name, 
	*(unsigned char *)(iff->hwaddr), *(unsigned char *)(iff->hwaddr+1),*(unsigned char *)(iff->hwaddr+2),
	*(unsigned char *)(iff->hwaddr+3), *(unsigned char *)(iff->hwaddr+4), *(unsigned char *)(iff->hwaddr+5), ntohl(iff->mtu), iff->flags, iface->ifi_flags);

	tmp->entries++;

	*iface_list = tmp;

    return 0;


}

struct iface_entry * find_iface_by_index(struct ifaces_list * list, uint32_t index)
{
	struct iface_entry * ret = NULL;
	uint32_t i;
	for(i=0; i<list->entries; i++) 
	{
		if (list->ifaces[i].index == index)
		{
			ret = &list->ifaces[i];
			break;
		}	

	}
	return ret;
}

struct iface_entry * find_iface_by_index_and_name(struct ifaces_list * list, uint32_t index,unsigned char * name)
{
	struct iface_entry * ret = NULL;
	uint32_t i;
	for(i=0; i<list->entries; i++) 
	{
		if (list->ifaces[i].index == index && !strcmp(list->ifaces[i].name, name))
		{
			ret = &list->ifaces[i];
			break;
		}	

	}
	return ret;
}

int netlink_parse_interface_address(struct nlmsghdr *nh, void *data)
{
	struct ifaces_list ** iface_list = ( struct ifaces_list **) data;
	struct iface_entry * iff;
	struct iface_entry * iff_tmp;
	struct ifaces_list  *tmp;
	struct iface_entry iface_tmp;

	struct ifaddrmsg *iaddr;
	struct rtattr *attribute;
	uint32_t len;
	uint32_t newsize;
	unsigned char is_ipv6;


	iaddr = NLMSG_DATA(nh);
	len = nh->nlmsg_len - NLMSG_LENGTH(sizeof(*iaddr));

	if (iaddr->ifa_family == AF_INET6)
		is_ipv6 = 1;
	else if (iaddr->ifa_family == AF_INET)
		is_ipv6 = 0;
	else {
		dprintf("[%s] Got iaddr->ifa_family : %d which is unknown (iaddr->ifa_index : %d)", __FUNCTION__,iaddr->ifa_family, iaddr->ifa_index);
		return 0;
	}

	memset(&iface_tmp, 0, sizeof(iface_tmp));
	for (attribute = IFA_RTA(iaddr); RTA_OK(attribute, len); attribute = RTA_NEXT(attribute, len))
	{
		switch(attribute->rta_type)
		{
			case IFA_ADDRESS:
				if (is_ipv6)
					memcpy(&iface_tmp.addr6, (unsigned char *) RTA_DATA(attribute), sizeof(__u128));
				else
					iface_tmp.addr = *(__u32 *) RTA_DATA(attribute);	
				break;

			case IFA_LABEL:
				strncpy(iface_tmp.name, (unsigned char *) RTA_DATA(attribute), IFNAMSIZ);
	      		break;
			default:
				break;
		}
	}

	dprintf("[%s] and while you're here, iaddr->ifa_prefixlen = %d", __FUNCTION__, iaddr->ifa_prefixlen);

	if (is_ipv6) {
		// if netmask is FFFFFFFF FFFFFFFF 00000000 00000000 (/64), netmask6.a1 and netmask6.a2 == 0xffffffff, and nestmask6.a3 and .a4 == 0
		// netmask6 is set to 0 at the beginning of the function, no need to reset the values to 0 if it is needed
		// XXX really ugly, but works
		if (iaddr->ifa_prefixlen >= 96) {
			iface_tmp.netmask6.a4 = (1 << (iaddr->ifa_prefixlen-96))-1;
			iface_tmp.netmask6.a1 = iface_tmp.netmask6.a2 = iface_tmp.netmask6.a3 =  0xffffffff;
		}
		else if (iaddr->ifa_prefixlen >= 64) {
			iface_tmp.netmask6.a3 = (1 << (iaddr->ifa_prefixlen-64))-1;
			iface_tmp.netmask6.a1 = iface_tmp.netmask6.a2 =  0xffffffff;
		}
		else if (iaddr->ifa_prefixlen >= 32) {
			iface_tmp.netmask6.a2 = (1 << (iaddr->ifa_prefixlen-32))-1;
			iface_tmp.netmask6.a1 =  0xffffffff;
		}
		else
			iface_tmp.netmask6.a1 = (1 << iaddr->ifa_prefixlen)-1;
	}
	else
		iface_tmp.netmask = ((1 << iaddr->ifa_prefixlen) - 1);


	/*
 	 * try to find the iface by index and name
	 * an IP alias (eth0:0 for instance) will have the same index but not the same name/label
	 * no alias when getting IPv6 address, so just search using the index
	 */
	if (is_ipv6) {
		iff = find_iface_by_index(*iface_list, iaddr->ifa_index);
		if (iff == NULL) {
			dprintf("[%s] Cannot find iface with index %d", __FUNCTION__,iaddr->ifa_index);
			return 0;
		}
	}
	else
		iff = find_iface_by_index_and_name(*iface_list, iaddr->ifa_index, iface_tmp.name);
	if (iff == NULL) {
		dprintf("[%s] %s an alias?", __FUNCTION__, iface_tmp.name);
		// didn't find this name, probably an alias such as eth0:0
		iff = find_iface_by_index(*iface_list, iaddr->ifa_index);
		if (iff == NULL) {
			dprintf("[%s] Cannot find iface with index %d", __FUNCTION__,iaddr->ifa_index);
			return 0;
		}
		// found it, copy the data to save it
		// old MAC addr and MTU
		memcpy(iface_tmp.hwaddr, iff->hwaddr, 6);
		iface_tmp.mtu = iff->mtu;
		iface_tmp.index = iff->index;
		memcpy(&iface_tmp.addr6, &iff->addr6, sizeof(__u128));
		memcpy(&iface_tmp.netmask6, &iff->netmask6, sizeof(__u128));
		strncpy(iface_tmp.flags, iff->flags, FLAGS_LEN);
		// allocate new one
		newsize  = sizeof(struct ifaces_list);
		newsize += ((*iface_list)->entries + 1) * sizeof(struct iface_entry);

		tmp = realloc(*iface_list, newsize);

		if(tmp == NULL) {
			return ENOMEM;
		}

		iff = &(tmp->ifaces[tmp->entries]);
		memset(iff, 0, sizeof(struct iface_entry));
		// copy back saved data in new iface_entry
		memcpy(iff->hwaddr, iface_tmp.hwaddr, 6);
		iff->mtu = iface_tmp.mtu;
		iff->index = iface_tmp.index;
		memcpy(&iff->addr6, &iface_tmp.addr6, sizeof(__u128));
		memcpy(&iff->netmask6, &iface_tmp.netmask6, sizeof(__u128));
		strncpy(iff->flags, iface_tmp.flags, FLAGS_LEN);
		// copy new name
		strncpy(iff->name, iface_tmp.name, IFNAMSIZ);

		tmp->entries++;
		*iface_list = tmp;
	}
	//now, iff points to a iface_entry, just copy add/addr6 and netmask/netmask6
	if (is_ipv6) {
		memcpy(&iff->addr6, &iface_tmp.addr6, sizeof(__u128));
		memcpy(&iff->netmask6, &iface_tmp.netmask6, sizeof(__u128));
	}
	else {
		iff->addr = iface_tmp.addr;
		iff->netmask = iface_tmp.netmask;
	}

	dprintf("[%s] iff->index = %d, iff->name = %s, iff->addr = %08x, iff->netmask = %08x, iff->addr6 = %08x %08x %08x %08x, iff->netmask6 = %08x %08x %08x %08x", 
	__FUNCTION__, iff->index, iff->name, iff->addr, iff->netmask,	
	iff->addr6.a1,iff->addr6.a2,iff->addr6.a3,iff->addr6.a4, iff->netmask6.a1,iff->netmask6.a2,iff->netmask6.a3,iff->netmask6.a4);

	return 0;
}


int netlink_get_interfaces(struct ifaces_list **iface_list)
{

	int fd;
	int seq;
	int status;

	*iface_list = NULL;

	*iface_list = calloc(sizeof(struct ifaces_list), 1);
	if(*iface_list == NULL) {
		return ENOMEM;
	}

	fd = netlink_socket(NETLINK_ROUTE);
	if(fd == -1) {
		dprintf("[%s] failed with netlink", __FUNCTION__);
		return ERROR_NOT_SUPPORTED;
	}

	seq = netlink_request(fd, AF_PACKET, RTM_GETLINK);
	if(seq == -1) {
		dprintf("[%s] netlink_request RTM_GETLINK failed", __FUNCTION__);
		close(fd);
		return ERROR_NOT_SUPPORTED;
	}

	// will create one iface_entry for each interface
	status = netlink_parse(fd, seq, netlink_parse_interface_link, iface_list);
	if(status != 0) {
        if (*iface_list)
		    free(*iface_list);
		*iface_list = NULL;
		return status;
	}

	seq = netlink_request(fd, AF_PACKET, RTM_GETADDR);
	if(seq == -1) {
		dprintf("[%s] netlink_request RTM_GETADDR failed", __FUNCTION__);
		close(fd);
		return ERROR_NOT_SUPPORTED;
	}
	// for each interface created before, will get the IPv4 / IPv6 addr
	status = netlink_parse(fd, seq,  netlink_parse_interface_address, iface_list);
	close(fd);
	if(status != 0) {
        if (*iface_list)
		    free(*iface_list);
		*iface_list = NULL;

	}

	return status;

}
