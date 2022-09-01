#ifndef OFFSETS_H
#define OFFSETS_H

#define IP_OBJECT_io_bits 0
#define IP_OBJECT_io_references 4
#define IP_OBJECT_io_lock_data_lock 8
#define IP_OBJECT_io_lock_data_type 0x10

#define IPC_PORT_ip_messages_imq_wait_queue 0x18
#define IPC_PORT_ip_messages_imq_next 0x1c
#define IPC_PORT_ip_messages_imq_prev 0x20
#define IPC_PORT_ip_messages_imq_msgcount 0x28
#define IPC_PORT_ip_messages_imq_qlimit 0x2c
#define IPC_PORT_kobject 0x44
#define IPC_PORT_receiver 0x40
#define IPC_PORT_ip_requests 0x50
#define IPC_PORT_ip_srights 0x5c 
#define IPC_PORT_flags 0x64
#define IPC_PORT_ip_context2 0x6c
#define IPC_PORT_ip_context 0x68

#define TASK_bsd_proc 0x1e8
#define TASK_itk_space 0x1a0
#define TASK_itk_self 0xa0

#define PROC_ucred 0x8c

#define SPACE_is_table_size 0x10
#define SPACE_is_table 0x14

// mount_common
#define VNODE_v_mount 0x84
#define MOUNT_mnt_flags 0x3c

#endif
