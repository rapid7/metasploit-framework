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
#ifndef _LINUX_SUNRPC_STATS_H
#define _LINUX_SUNRPC_STATS_H

#include <linux/proc_fs.h>

struct rpc_stat {
 struct rpc_program * program;

 unsigned int netcnt,
 netudpcnt,
 nettcpcnt,
 nettcpconn,
 netreconn;
 unsigned int rpccnt,
 rpcretrans,
 rpcauthrefresh,
 rpcgarbage;
};

struct svc_stat {
 struct svc_program * program;

 unsigned int netcnt,
 netudpcnt,
 nettcpcnt,
 nettcpconn;
 unsigned int rpccnt,
 rpcbadfmt,
 rpcbadauth,
 rpcbadclnt;
};

#ifdef MODULE

#endif

#define proc_net_rpc NULL
#endif
