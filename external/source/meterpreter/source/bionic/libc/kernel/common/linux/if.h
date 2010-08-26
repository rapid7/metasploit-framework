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
#ifndef _LINUX_IF_H
#define _LINUX_IF_H

#include <linux/types.h>  
#include <linux/socket.h>  
#include <linux/compiler.h>  

#define IFNAMSIZ 16
#include <linux/hdlc/ioctl.h>

#define IFF_UP 0x1  
#define IFF_BROADCAST 0x2  
#define IFF_DEBUG 0x4  
#define IFF_LOOPBACK 0x8  
#define IFF_POINTOPOINT 0x10  
#define IFF_NOTRAILERS 0x20  
#define IFF_RUNNING 0x40  
#define IFF_NOARP 0x80  
#define IFF_PROMISC 0x100  
#define IFF_ALLMULTI 0x200  

#define IFF_MASTER 0x400  
#define IFF_SLAVE 0x800  

#define IFF_MULTICAST 0x1000  

#define IFF_PORTSEL 0x2000  
#define IFF_AUTOMEDIA 0x4000  
#define IFF_DYNAMIC 0x8000  

#define IFF_LOWER_UP 0x10000  
#define IFF_DORMANT 0x20000  

#define IFF_VOLATILE (IFF_LOOPBACK|IFF_POINTOPOINT|IFF_BROADCAST|  IFF_MASTER|IFF_SLAVE|IFF_RUNNING|IFF_LOWER_UP|IFF_DORMANT)

#define IFF_802_1Q_VLAN 0x1  
#define IFF_EBRIDGE 0x2  
#define IFF_SLAVE_INACTIVE 0x4  
#define IFF_MASTER_8023AD 0x8  
#define IFF_MASTER_ALB 0x10  

#define IF_GET_IFACE 0x0001  
#define IF_GET_PROTO 0x0002

#define IF_IFACE_V35 0x1000  
#define IF_IFACE_V24 0x1001  
#define IF_IFACE_X21 0x1002  
#define IF_IFACE_T1 0x1003  
#define IF_IFACE_E1 0x1004  
#define IF_IFACE_SYNC_SERIAL 0x1005  
#define IF_IFACE_X21D 0x1006  

#define IF_PROTO_HDLC 0x2000  
#define IF_PROTO_PPP 0x2001  
#define IF_PROTO_CISCO 0x2002  
#define IF_PROTO_FR 0x2003  
#define IF_PROTO_FR_ADD_PVC 0x2004  
#define IF_PROTO_FR_DEL_PVC 0x2005  
#define IF_PROTO_X25 0x2006  
#define IF_PROTO_HDLC_ETH 0x2007  
#define IF_PROTO_FR_ADD_ETH_PVC 0x2008  
#define IF_PROTO_FR_DEL_ETH_PVC 0x2009  
#define IF_PROTO_FR_PVC 0x200A  
#define IF_PROTO_FR_ETH_PVC 0x200B
#define IF_PROTO_RAW 0x200C  

enum {
 IF_OPER_UNKNOWN,
 IF_OPER_NOTPRESENT,
 IF_OPER_DOWN,
 IF_OPER_LOWERLAYERDOWN,
 IF_OPER_TESTING,
 IF_OPER_DORMANT,
 IF_OPER_UP,
};

enum {
 IF_LINK_MODE_DEFAULT,
 IF_LINK_MODE_DORMANT,
};

struct ifmap
{
 unsigned long mem_start;
 unsigned long mem_end;
 unsigned short base_addr;
 unsigned char irq;
 unsigned char dma;
 unsigned char port;

};

struct if_settings
{
 unsigned int type;
 unsigned int size;
 union {

 raw_hdlc_proto __user *raw_hdlc;
 cisco_proto __user *cisco;
 fr_proto __user *fr;
 fr_proto_pvc __user *fr_pvc;
 fr_proto_pvc_info __user *fr_pvc_info;

 sync_serial_settings __user *sync;
 te1_settings __user *te1;
 } ifs_ifsu;
};

struct ifreq
{
#define IFHWADDRLEN 6
 union
 {
 char ifrn_name[IFNAMSIZ];
 } ifr_ifrn;

 union {
 struct sockaddr ifru_addr;
 struct sockaddr ifru_dstaddr;
 struct sockaddr ifru_broadaddr;
 struct sockaddr ifru_netmask;
 struct sockaddr ifru_hwaddr;
 short ifru_flags;
 int ifru_ivalue;
 int ifru_mtu;
 struct ifmap ifru_map;
 char ifru_slave[IFNAMSIZ];
 char ifru_newname[IFNAMSIZ];
 void __user * ifru_data;
 struct if_settings ifru_settings;
 } ifr_ifru;
};

#define ifr_name ifr_ifrn.ifrn_name  
#define ifr_hwaddr ifr_ifru.ifru_hwaddr  
#define ifr_addr ifr_ifru.ifru_addr  
#define ifr_dstaddr ifr_ifru.ifru_dstaddr  
#define ifr_broadaddr ifr_ifru.ifru_broadaddr  
#define ifr_netmask ifr_ifru.ifru_netmask  
#define ifr_flags ifr_ifru.ifru_flags  
#define ifr_metric ifr_ifru.ifru_ivalue  
#define ifr_mtu ifr_ifru.ifru_mtu  
#define ifr_map ifr_ifru.ifru_map  
#define ifr_slave ifr_ifru.ifru_slave  
#define ifr_data ifr_ifru.ifru_data  
#define ifr_ifindex ifr_ifru.ifru_ivalue  
#define ifr_bandwidth ifr_ifru.ifru_ivalue  
#define ifr_qlen ifr_ifru.ifru_ivalue  
#define ifr_newname ifr_ifru.ifru_newname  
#define ifr_settings ifr_ifru.ifru_settings  

struct ifconf
{
 int ifc_len;
 union
 {
 char __user *ifcu_buf;
 struct ifreq __user *ifcu_req;
 } ifc_ifcu;
};
#define ifc_buf ifc_ifcu.ifcu_buf  
#define ifc_req ifc_ifcu.ifcu_req  

#endif
