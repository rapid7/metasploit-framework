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
#ifndef _LINUX_BINDER_H
#define _LINUX_BINDER_H

#include <linux/ioctl.h>

#define B_PACK_CHARS(c1, c2, c3, c4)   ((((c1)<<24)) | (((c2)<<16)) | (((c3)<<8)) | (c4))
#define B_TYPE_LARGE 0x85

enum {
 BINDER_TYPE_BINDER = B_PACK_CHARS('s', 'b', '*', B_TYPE_LARGE),
 BINDER_TYPE_WEAK_BINDER = B_PACK_CHARS('w', 'b', '*', B_TYPE_LARGE),
 BINDER_TYPE_HANDLE = B_PACK_CHARS('s', 'h', '*', B_TYPE_LARGE),
 BINDER_TYPE_WEAK_HANDLE = B_PACK_CHARS('w', 'h', '*', B_TYPE_LARGE),
 BINDER_TYPE_FD = B_PACK_CHARS('f', 'd', '*', B_TYPE_LARGE),
};

enum {
 FLAT_BINDER_FLAG_PRIORITY_MASK = 0xff,
 FLAT_BINDER_FLAG_ACCEPTS_FDS = 0x100,
};

struct flat_binder_object {

 unsigned long type;
 unsigned long flags;

 union {
 void *binder;
 signed long handle;
 };

 void *cookie;
};

struct binder_write_read {
 signed long write_size;
 signed long write_consumed;
 unsigned long write_buffer;
 signed long read_size;
 signed long read_consumed;
 unsigned long read_buffer;
};

struct binder_version {

 signed long protocol_version;
};

#define BINDER_CURRENT_PROTOCOL_VERSION 7

#define BINDER_WRITE_READ _IOWR('b', 1, struct binder_write_read)
#define BINDER_SET_IDLE_TIMEOUT _IOW('b', 3, int64_t)
#define BINDER_SET_MAX_THREADS _IOW('b', 5, size_t)
#define BINDER_SET_IDLE_PRIORITY _IOW('b', 6, int)
#define BINDER_SET_CONTEXT_MGR _IOW('b', 7, int)
#define BINDER_THREAD_EXIT _IOW('b', 8, int)
#define BINDER_VERSION _IOWR('b', 9, struct binder_version)

enum transaction_flags {
 TF_ONE_WAY = 0x01,
 TF_ROOT_OBJECT = 0x04,
 TF_STATUS_CODE = 0x08,
 TF_ACCEPT_FDS = 0x10,
};

struct binder_transaction_data {

 union {
 size_t handle;
 void *ptr;
 } target;
 void *cookie;
 unsigned int code;

 unsigned int flags;
 pid_t sender_pid;
 uid_t sender_euid;
 size_t data_size;
 size_t offsets_size;

 union {
 struct {

 const void *buffer;

 const void *offsets;
 } ptr;
 uint8_t buf[8];
 } data;
};

struct binder_ptr_cookie {
 void *ptr;
 void *cookie;
};

struct binder_pri_desc {
 int priority;
 int desc;
};

struct binder_pri_ptr_cookie {
 int priority;
 void *ptr;
 void *cookie;
};

enum BinderDriverReturnProtocol {
 BR_ERROR = _IOR_BAD('r', 0, int),

 BR_OK = _IO('r', 1),

 BR_TRANSACTION = _IOR_BAD('r', 2, struct binder_transaction_data),
 BR_REPLY = _IOR_BAD('r', 3, struct binder_transaction_data),

 BR_ACQUIRE_RESULT = _IOR_BAD('r', 4, int),

 BR_DEAD_REPLY = _IO('r', 5),

 BR_TRANSACTION_COMPLETE = _IO('r', 6),

 BR_INCREFS = _IOR_BAD('r', 7, struct binder_ptr_cookie),
 BR_ACQUIRE = _IOR_BAD('r', 8, struct binder_ptr_cookie),
 BR_RELEASE = _IOR_BAD('r', 9, struct binder_ptr_cookie),
 BR_DECREFS = _IOR_BAD('r', 10, struct binder_ptr_cookie),

 BR_ATTEMPT_ACQUIRE = _IOR_BAD('r', 11, struct binder_pri_ptr_cookie),

 BR_NOOP = _IO('r', 12),

 BR_SPAWN_LOOPER = _IO('r', 13),

 BR_FINISHED = _IO('r', 14),

 BR_DEAD_BINDER = _IOR_BAD('r', 15, void *),

 BR_CLEAR_DEATH_NOTIFICATION_DONE = _IOR_BAD('r', 16, void *),

 BR_FAILED_REPLY = _IO('r', 17),

};

enum BinderDriverCommandProtocol {
 BC_TRANSACTION = _IOW_BAD('c', 0, struct binder_transaction_data),
 BC_REPLY = _IOW_BAD('c', 1, struct binder_transaction_data),

 BC_ACQUIRE_RESULT = _IOW_BAD('c', 2, int),

 BC_FREE_BUFFER = _IOW_BAD('c', 3, int),

 BC_INCREFS = _IOW_BAD('c', 4, int),
 BC_ACQUIRE = _IOW_BAD('c', 5, int),
 BC_RELEASE = _IOW_BAD('c', 6, int),
 BC_DECREFS = _IOW_BAD('c', 7, int),

 BC_INCREFS_DONE = _IOW_BAD('c', 8, struct binder_ptr_cookie),
 BC_ACQUIRE_DONE = _IOW_BAD('c', 9, struct binder_ptr_cookie),

 BC_ATTEMPT_ACQUIRE = _IOW_BAD('c', 10, struct binder_pri_desc),

 BC_REGISTER_LOOPER = _IO('c', 11),

 BC_ENTER_LOOPER = _IO('c', 12),
 BC_EXIT_LOOPER = _IO('c', 13),

 BC_REQUEST_DEATH_NOTIFICATION = _IOW_BAD('c', 14, struct binder_ptr_cookie),

 BC_CLEAR_DEATH_NOTIFICATION = _IOW_BAD('c', 15, struct binder_ptr_cookie),

 BC_DEAD_BINDER_DONE = _IOW_BAD('c', 16, void *),

};

#endif

