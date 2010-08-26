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
#ifndef _LINUX_NETDEVICE_H
#define _LINUX_NETDEVICE_H

#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#define MAX_ADDR_LEN 32  

#define NETDEV_TX_OK 0  
#define NETDEV_TX_BUSY 1  
#define NETDEV_TX_LOCKED -1  

#define LL_MAX_HEADER 32

#define MAX_HEADER LL_MAX_HEADER

struct net_device_stats
{
 unsigned long rx_packets;
 unsigned long tx_packets;
 unsigned long rx_bytes;
 unsigned long tx_bytes;
 unsigned long rx_errors;
 unsigned long tx_errors;
 unsigned long rx_dropped;
 unsigned long tx_dropped;
 unsigned long multicast;
 unsigned long collisions;

 unsigned long rx_length_errors;
 unsigned long rx_over_errors;
 unsigned long rx_crc_errors;
 unsigned long rx_frame_errors;
 unsigned long rx_fifo_errors;
 unsigned long rx_missed_errors;

 unsigned long tx_aborted_errors;
 unsigned long tx_carrier_errors;
 unsigned long tx_fifo_errors;
 unsigned long tx_heartbeat_errors;
 unsigned long tx_window_errors;

 unsigned long rx_compressed;
 unsigned long tx_compressed;
};

enum {
 IF_PORT_UNKNOWN = 0,
 IF_PORT_10BASE2,
 IF_PORT_10BASET,
 IF_PORT_AUI,
 IF_PORT_100BASET,
 IF_PORT_100BASETX,
 IF_PORT_100BASEFX
};

#endif
