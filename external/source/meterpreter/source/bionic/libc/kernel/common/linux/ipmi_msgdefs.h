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
#ifndef __LINUX_IPMI_MSGDEFS_H
#define __LINUX_IPMI_MSGDEFS_H

#define IPMI_NETFN_SENSOR_EVENT_REQUEST 0x04
#define IPMI_NETFN_SENSOR_EVENT_RESPONSE 0x05
#define IPMI_GET_EVENT_RECEIVER_CMD 0x01

#define IPMI_NETFN_APP_REQUEST 0x06
#define IPMI_NETFN_APP_RESPONSE 0x07
#define IPMI_GET_DEVICE_ID_CMD 0x01
#define IPMI_CLEAR_MSG_FLAGS_CMD 0x30
#define IPMI_GET_DEVICE_GUID_CMD 0x08
#define IPMI_GET_MSG_FLAGS_CMD 0x31
#define IPMI_SEND_MSG_CMD 0x34
#define IPMI_GET_MSG_CMD 0x33
#define IPMI_SET_BMC_GLOBAL_ENABLES_CMD 0x2e
#define IPMI_GET_BMC_GLOBAL_ENABLES_CMD 0x2f
#define IPMI_READ_EVENT_MSG_BUFFER_CMD 0x35
#define IPMI_GET_CHANNEL_INFO_CMD 0x42

#define IPMI_NETFN_STORAGE_REQUEST 0x0a
#define IPMI_NETFN_STORAGE_RESPONSE 0x0b
#define IPMI_ADD_SEL_ENTRY_CMD 0x44

#define IPMI_BMC_SLAVE_ADDR 0x20

#define IPMI_MAX_MSG_LENGTH 272  

#define IPMI_CC_NO_ERROR 0x00
#define IPMI_NODE_BUSY_ERR 0xc0
#define IPMI_INVALID_COMMAND_ERR 0xc1
#define IPMI_ERR_MSG_TRUNCATED 0xc6
#define IPMI_LOST_ARBITRATION_ERR 0x81
#define IPMI_ERR_UNSPECIFIED 0xff

#define IPMI_CHANNEL_PROTOCOL_IPMB 1
#define IPMI_CHANNEL_PROTOCOL_ICMB 2
#define IPMI_CHANNEL_PROTOCOL_SMBUS 4
#define IPMI_CHANNEL_PROTOCOL_KCS 5
#define IPMI_CHANNEL_PROTOCOL_SMIC 6
#define IPMI_CHANNEL_PROTOCOL_BT10 7
#define IPMI_CHANNEL_PROTOCOL_BT15 8
#define IPMI_CHANNEL_PROTOCOL_TMODE 9

#define IPMI_CHANNEL_MEDIUM_IPMB 1
#define IPMI_CHANNEL_MEDIUM_ICMB10 2
#define IPMI_CHANNEL_MEDIUM_ICMB09 3
#define IPMI_CHANNEL_MEDIUM_8023LAN 4
#define IPMI_CHANNEL_MEDIUM_ASYNC 5
#define IPMI_CHANNEL_MEDIUM_OTHER_LAN 6
#define IPMI_CHANNEL_MEDIUM_PCI_SMBUS 7
#define IPMI_CHANNEL_MEDIUM_SMBUS1 8
#define IPMI_CHANNEL_MEDIUM_SMBUS2 9
#define IPMI_CHANNEL_MEDIUM_USB1 10
#define IPMI_CHANNEL_MEDIUM_USB2 11
#define IPMI_CHANNEL_MEDIUM_SYSINTF 12

#endif
