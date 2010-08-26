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
#ifndef _LINUX_SUNRPC_XPRT_H
#define _LINUX_SUNRPC_XPRT_H

#include <linux/uio.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/sunrpc/sched.h>
#include <linux/sunrpc/xdr.h>

#define RPC_MIN_SLOT_TABLE (2U)
#define RPC_DEF_SLOT_TABLE (16U)
#define RPC_MAX_SLOT_TABLE (128U)

#define RPC_CALLHDRSIZE 6
#define RPC_REPHDRSIZE 4

#define RPC_MIN_RESVPORT (1U)
#define RPC_MAX_RESVPORT (65535U)
#define RPC_DEF_MIN_RESVPORT (665U)
#define RPC_DEF_MAX_RESVPORT (1023U)

struct rpc_timeout {
 unsigned long to_initval,
 to_maxval,
 to_increment;
 unsigned int to_retries;
 unsigned char to_exponential;
};

struct rpc_task;
struct rpc_xprt;
struct seq_file;

struct rpc_rqst {

 struct rpc_xprt * rq_xprt;
 struct xdr_buf rq_snd_buf;
 struct xdr_buf rq_rcv_buf;

 struct rpc_task * rq_task;
 __u32 rq_xid;
 int rq_cong;
 int rq_received;
 u32 rq_seqno;
 int rq_enc_pages_num;
 struct page **rq_enc_pages;
 void (*rq_release_snd_buf)(struct rpc_rqst *);
 struct list_head rq_list;

 __u32 * rq_buffer;
 size_t rq_bufsize;

 struct xdr_buf rq_private_buf;
 unsigned long rq_majortimeo;
 unsigned long rq_timeout;
 unsigned int rq_retries;

 u32 rq_bytes_sent;

 unsigned long rq_xtime;
 int rq_ntrans;
};
#define rq_svec rq_snd_buf.head
#define rq_slen rq_snd_buf.len

struct rpc_xprt_ops {
 void (*set_buffer_size)(struct rpc_xprt *xprt, size_t sndsize, size_t rcvsize);
 int (*reserve_xprt)(struct rpc_task *task);
 void (*release_xprt)(struct rpc_xprt *xprt, struct rpc_task *task);
 void (*set_port)(struct rpc_xprt *xprt, unsigned short port);
 void (*connect)(struct rpc_task *task);
 void * (*buf_alloc)(struct rpc_task *task, size_t size);
 void (*buf_free)(struct rpc_task *task);
 int (*send_request)(struct rpc_task *task);
 void (*set_retrans_timeout)(struct rpc_task *task);
 void (*timer)(struct rpc_task *task);
 void (*release_request)(struct rpc_task *task);
 void (*close)(struct rpc_xprt *xprt);
 void (*destroy)(struct rpc_xprt *xprt);
 void (*print_stats)(struct rpc_xprt *xprt, struct seq_file *seq);
};

struct rpc_xprt {
 struct rpc_xprt_ops * ops;
 struct socket * sock;
 struct sock * inet;

 struct rpc_timeout timeout;
 struct sockaddr_in addr;
 int prot;

 unsigned long cong;
 unsigned long cwnd;

 size_t rcvsize,
 sndsize;

 size_t max_payload;
 unsigned int tsh_size;

 struct rpc_wait_queue sending;
 struct rpc_wait_queue resend;
 struct rpc_wait_queue pending;
 struct rpc_wait_queue backlog;
 struct list_head free;
 struct rpc_rqst * slot;
 unsigned int max_reqs;
 unsigned long state;
 unsigned char shutdown : 1,
 resvport : 1;

 __u32 xid;

 u32 tcp_recm,
 tcp_xid,
 tcp_reclen,
 tcp_offset;
 unsigned long tcp_copied,
 tcp_flags;

 unsigned long connect_timeout,
 bind_timeout,
 reestablish_timeout;
 struct work_struct connect_worker;
 unsigned short port;

 struct work_struct task_cleanup;
 struct timer_list timer;
 unsigned long last_used,
 idle_timeout;

 spinlock_t transport_lock;
 spinlock_t reserve_lock;
 struct rpc_task * snd_task;

 struct list_head recv;

 struct {
 unsigned long bind_count,
 connect_count,
 connect_start,
 connect_time,
 sends,
 recvs,
 bad_xids;

 unsigned long long req_u,
 bklog_u;
 } stat;

 void (*old_data_ready)(struct sock *, int);
 void (*old_state_change)(struct sock *);
 void (*old_write_space)(struct sock *);
};

#define XPRT_LAST_FRAG (1 << 0)
#define XPRT_COPY_RECM (1 << 1)
#define XPRT_COPY_XID (1 << 2)
#define XPRT_COPY_DATA (1 << 3)

#endif
