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
#ifndef __LINUX_IPMI_SMI_H
#define __LINUX_IPMI_SMI_H

#include <linux/ipmi_msgdefs.h>
#include <linux/proc_fs.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/ipmi_smi.h>

typedef struct ipmi_smi *ipmi_smi_t;

struct ipmi_smi_msg
{
 struct list_head link;

 long msgid;
 void *user_data;

 int data_size;
 unsigned char data[IPMI_MAX_MSG_LENGTH];

 int rsp_size;
 unsigned char rsp[IPMI_MAX_MSG_LENGTH];

 void (*done)(struct ipmi_smi_msg *msg);
};

struct ipmi_smi_handlers
{
 struct module *owner;

 int (*start_processing)(void *send_info,
 ipmi_smi_t new_intf);

 void (*sender)(void *send_info,
 struct ipmi_smi_msg *msg,
 int priority);

 void (*request_events)(void *send_info);

 void (*set_run_to_completion)(void *send_info, int run_to_completion);

 void (*poll)(void *send_info);

 int (*inc_usecount)(void *send_info);
 void (*dec_usecount)(void *send_info);
};

struct ipmi_device_id {
 unsigned char device_id;
 unsigned char device_revision;
 unsigned char firmware_revision_1;
 unsigned char firmware_revision_2;
 unsigned char ipmi_version;
 unsigned char additional_device_support;
 unsigned int manufacturer_id;
 unsigned int product_id;
 unsigned char aux_firmware_revision[4];
 unsigned int aux_firmware_revision_set : 1;
};

#define ipmi_version_major(v) ((v)->ipmi_version & 0xf)
#define ipmi_version_minor(v) ((v)->ipmi_version >> 4)

struct ipmi_smi_msg *ipmi_alloc_smi_msg(void);

#endif
