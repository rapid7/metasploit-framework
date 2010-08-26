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
#ifndef __LINUX_USB_CH9_H
#define __LINUX_USB_CH9_H

#include <linux/types.h>  

#define USB_DIR_OUT 0  
#define USB_DIR_IN 0x80  

#define USB_TYPE_MASK (0x03 << 5)
#define USB_TYPE_STANDARD (0x00 << 5)
#define USB_TYPE_CLASS (0x01 << 5)
#define USB_TYPE_VENDOR (0x02 << 5)
#define USB_TYPE_RESERVED (0x03 << 5)

#define USB_RECIP_MASK 0x1f
#define USB_RECIP_DEVICE 0x00
#define USB_RECIP_INTERFACE 0x01
#define USB_RECIP_ENDPOINT 0x02
#define USB_RECIP_OTHER 0x03

#define USB_RECIP_PORT 0x04
#define USB_RECIP_RPIPE 0x05

#define USB_REQ_GET_STATUS 0x00
#define USB_REQ_CLEAR_FEATURE 0x01
#define USB_REQ_SET_FEATURE 0x03
#define USB_REQ_SET_ADDRESS 0x05
#define USB_REQ_GET_DESCRIPTOR 0x06
#define USB_REQ_SET_DESCRIPTOR 0x07
#define USB_REQ_GET_CONFIGURATION 0x08
#define USB_REQ_SET_CONFIGURATION 0x09
#define USB_REQ_GET_INTERFACE 0x0A
#define USB_REQ_SET_INTERFACE 0x0B
#define USB_REQ_SYNCH_FRAME 0x0C

#define USB_REQ_SET_ENCRYPTION 0x0D  
#define USB_REQ_GET_ENCRYPTION 0x0E
#define USB_REQ_RPIPE_ABORT 0x0E
#define USB_REQ_SET_HANDSHAKE 0x0F
#define USB_REQ_RPIPE_RESET 0x0F
#define USB_REQ_GET_HANDSHAKE 0x10
#define USB_REQ_SET_CONNECTION 0x11
#define USB_REQ_SET_SECURITY_DATA 0x12
#define USB_REQ_GET_SECURITY_DATA 0x13
#define USB_REQ_SET_WUSB_DATA 0x14
#define USB_REQ_LOOPBACK_DATA_WRITE 0x15
#define USB_REQ_LOOPBACK_DATA_READ 0x16
#define USB_REQ_SET_INTERFACE_DS 0x17

#define USB_DEVICE_SELF_POWERED 0  
#define USB_DEVICE_REMOTE_WAKEUP 1  
#define USB_DEVICE_TEST_MODE 2  
#define USB_DEVICE_BATTERY 2  
#define USB_DEVICE_B_HNP_ENABLE 3  
#define USB_DEVICE_WUSB_DEVICE 3  
#define USB_DEVICE_A_HNP_SUPPORT 4  
#define USB_DEVICE_A_ALT_HNP_SUPPORT 5  
#define USB_DEVICE_DEBUG_MODE 6  

#define USB_ENDPOINT_HALT 0  

struct usb_ctrlrequest {
 __u8 bRequestType;
 __u8 bRequest;
 __le16 wValue;
 __le16 wIndex;
 __le16 wLength;
} __attribute__ ((packed));

#define USB_DT_DEVICE 0x01
#define USB_DT_CONFIG 0x02
#define USB_DT_STRING 0x03
#define USB_DT_INTERFACE 0x04
#define USB_DT_ENDPOINT 0x05
#define USB_DT_DEVICE_QUALIFIER 0x06
#define USB_DT_OTHER_SPEED_CONFIG 0x07
#define USB_DT_INTERFACE_POWER 0x08

#define USB_DT_OTG 0x09
#define USB_DT_DEBUG 0x0a
#define USB_DT_INTERFACE_ASSOCIATION 0x0b

#define USB_DT_SECURITY 0x0c
#define USB_DT_KEY 0x0d
#define USB_DT_ENCRYPTION_TYPE 0x0e
#define USB_DT_BOS 0x0f
#define USB_DT_DEVICE_CAPABILITY 0x10
#define USB_DT_WIRELESS_ENDPOINT_COMP 0x11
#define USB_DT_WIRE_ADAPTER 0x21
#define USB_DT_RPIPE 0x22

#define USB_DT_CS_DEVICE 0x21
#define USB_DT_CS_CONFIG 0x22
#define USB_DT_CS_STRING 0x23
#define USB_DT_CS_INTERFACE 0x24
#define USB_DT_CS_ENDPOINT 0x25

struct usb_descriptor_header {
 __u8 bLength;
 __u8 bDescriptorType;
} __attribute__ ((packed));

struct usb_device_descriptor {
 __u8 bLength;
 __u8 bDescriptorType;

 __le16 bcdUSB;
 __u8 bDeviceClass;
 __u8 bDeviceSubClass;
 __u8 bDeviceProtocol;
 __u8 bMaxPacketSize0;
 __le16 idVendor;
 __le16 idProduct;
 __le16 bcdDevice;
 __u8 iManufacturer;
 __u8 iProduct;
 __u8 iSerialNumber;
 __u8 bNumConfigurations;
} __attribute__ ((packed));

#define USB_DT_DEVICE_SIZE 18

#define USB_CLASS_PER_INTERFACE 0  
#define USB_CLASS_AUDIO 1
#define USB_CLASS_COMM 2
#define USB_CLASS_HID 3
#define USB_CLASS_PHYSICAL 5
#define USB_CLASS_STILL_IMAGE 6
#define USB_CLASS_PRINTER 7
#define USB_CLASS_MASS_STORAGE 8
#define USB_CLASS_HUB 9
#define USB_CLASS_CDC_DATA 0x0a
#define USB_CLASS_CSCID 0x0b  
#define USB_CLASS_CONTENT_SEC 0x0d  
#define USB_CLASS_VIDEO 0x0e
#define USB_CLASS_WIRELESS_CONTROLLER 0xe0
#define USB_CLASS_APP_SPEC 0xfe
#define USB_CLASS_VENDOR_SPEC 0xff

struct usb_config_descriptor {
 __u8 bLength;
 __u8 bDescriptorType;

 __le16 wTotalLength;
 __u8 bNumInterfaces;
 __u8 bConfigurationValue;
 __u8 iConfiguration;
 __u8 bmAttributes;
 __u8 bMaxPower;
} __attribute__ ((packed));

#define USB_DT_CONFIG_SIZE 9

#define USB_CONFIG_ATT_ONE (1 << 7)  
#define USB_CONFIG_ATT_SELFPOWER (1 << 6)  
#define USB_CONFIG_ATT_WAKEUP (1 << 5)  
#define USB_CONFIG_ATT_BATTERY (1 << 4)  

struct usb_string_descriptor {
 __u8 bLength;
 __u8 bDescriptorType;

 __le16 wData[1];
} __attribute__ ((packed));

struct usb_interface_descriptor {
 __u8 bLength;
 __u8 bDescriptorType;

 __u8 bInterfaceNumber;
 __u8 bAlternateSetting;
 __u8 bNumEndpoints;
 __u8 bInterfaceClass;
 __u8 bInterfaceSubClass;
 __u8 bInterfaceProtocol;
 __u8 iInterface;
} __attribute__ ((packed));

#define USB_DT_INTERFACE_SIZE 9

struct usb_endpoint_descriptor {
 __u8 bLength;
 __u8 bDescriptorType;

 __u8 bEndpointAddress;
 __u8 bmAttributes;
 __le16 wMaxPacketSize;
 __u8 bInterval;

 __u8 bRefresh;
 __u8 bSynchAddress;
} __attribute__ ((packed));

#define USB_DT_ENDPOINT_SIZE 7
#define USB_DT_ENDPOINT_AUDIO_SIZE 9  

#define USB_ENDPOINT_NUMBER_MASK 0x0f  
#define USB_ENDPOINT_DIR_MASK 0x80

#define USB_ENDPOINT_XFERTYPE_MASK 0x03  
#define USB_ENDPOINT_XFER_CONTROL 0
#define USB_ENDPOINT_XFER_ISOC 1
#define USB_ENDPOINT_XFER_BULK 2
#define USB_ENDPOINT_XFER_INT 3
#define USB_ENDPOINT_MAX_ADJUSTABLE 0x80

struct usb_qualifier_descriptor {
 __u8 bLength;
 __u8 bDescriptorType;

 __le16 bcdUSB;
 __u8 bDeviceClass;
 __u8 bDeviceSubClass;
 __u8 bDeviceProtocol;
 __u8 bMaxPacketSize0;
 __u8 bNumConfigurations;
 __u8 bRESERVED;
} __attribute__ ((packed));

struct usb_otg_descriptor {
 __u8 bLength;
 __u8 bDescriptorType;

 __u8 bmAttributes;
} __attribute__ ((packed));

#define USB_OTG_SRP (1 << 0)
#define USB_OTG_HNP (1 << 1)  

struct usb_debug_descriptor {
 __u8 bLength;
 __u8 bDescriptorType;

 __u8 bDebugInEndpoint;
 __u8 bDebugOutEndpoint;
};

struct usb_interface_assoc_descriptor {
 __u8 bLength;
 __u8 bDescriptorType;

 __u8 bFirstInterface;
 __u8 bInterfaceCount;
 __u8 bFunctionClass;
 __u8 bFunctionSubClass;
 __u8 bFunctionProtocol;
 __u8 iFunction;
} __attribute__ ((packed));

struct usb_security_descriptor {
 __u8 bLength;
 __u8 bDescriptorType;

 __le16 wTotalLength;
 __u8 bNumEncryptionTypes;
};

struct usb_key_descriptor {
 __u8 bLength;
 __u8 bDescriptorType;

 __u8 tTKID[3];
 __u8 bReserved;
 __u8 bKeyData[0];
};

struct usb_encryption_descriptor {
 __u8 bLength;
 __u8 bDescriptorType;

 __u8 bEncryptionType;
#define USB_ENC_TYPE_UNSECURE 0
#define USB_ENC_TYPE_WIRED 1  
#define USB_ENC_TYPE_CCM_1 2  
#define USB_ENC_TYPE_RSA_1 3  
 __u8 bEncryptionValue;
 __u8 bAuthKeyIndex;
};

struct usb_bos_descriptor {
 __u8 bLength;
 __u8 bDescriptorType;

 __le16 wTotalLength;
 __u8 bNumDeviceCaps;
};

struct usb_dev_cap_header {
 __u8 bLength;
 __u8 bDescriptorType;
 __u8 bDevCapabilityType;
};

#define USB_CAP_TYPE_WIRELESS_USB 1

struct usb_wireless_cap_descriptor {
 __u8 bLength;
 __u8 bDescriptorType;
 __u8 bDevCapabilityType;

 __u8 bmAttributes;
#define USB_WIRELESS_P2P_DRD (1 << 1)
#define USB_WIRELESS_BEACON_MASK (3 << 2)
#define USB_WIRELESS_BEACON_SELF (1 << 2)
#define USB_WIRELESS_BEACON_DIRECTED (2 << 2)
#define USB_WIRELESS_BEACON_NONE (3 << 2)
 __le16 wPHYRates;
#define USB_WIRELESS_PHY_53 (1 << 0)  
#define USB_WIRELESS_PHY_80 (1 << 1)
#define USB_WIRELESS_PHY_107 (1 << 2)  
#define USB_WIRELESS_PHY_160 (1 << 3)
#define USB_WIRELESS_PHY_200 (1 << 4)  
#define USB_WIRELESS_PHY_320 (1 << 5)
#define USB_WIRELESS_PHY_400 (1 << 6)
#define USB_WIRELESS_PHY_480 (1 << 7)
 __u8 bmTFITXPowerInfo;
 __u8 bmFFITXPowerInfo;
 __le16 bmBandGroup;
 __u8 bReserved;
};

struct usb_wireless_ep_comp_descriptor {
 __u8 bLength;
 __u8 bDescriptorType;

 __u8 bMaxBurst;
 __u8 bMaxSequence;
 __le16 wMaxStreamDelay;
 __le16 wOverTheAirPacketSize;
 __u8 bOverTheAirInterval;
 __u8 bmCompAttributes;
#define USB_ENDPOINT_SWITCH_MASK 0x03  
#define USB_ENDPOINT_SWITCH_NO 0
#define USB_ENDPOINT_SWITCH_SWITCH 1
#define USB_ENDPOINT_SWITCH_SCALE 2
};

struct usb_handshake {
 __u8 bMessageNumber;
 __u8 bStatus;
 __u8 tTKID[3];
 __u8 bReserved;
 __u8 CDID[16];
 __u8 nonce[16];
 __u8 MIC[8];
};

struct usb_connection_context {
 __u8 CHID[16];
 __u8 CDID[16];
 __u8 CK[16];
};

enum usb_device_speed {
 USB_SPEED_UNKNOWN = 0,
 USB_SPEED_LOW, USB_SPEED_FULL,
 USB_SPEED_HIGH,
 USB_SPEED_VARIABLE,
};

enum usb_device_state {

 USB_STATE_NOTATTACHED = 0,

 USB_STATE_ATTACHED,
 USB_STATE_POWERED,
 USB_STATE_UNAUTHENTICATED,
 USB_STATE_RECONNECTING,
 USB_STATE_DEFAULT,
 USB_STATE_ADDRESS,
 USB_STATE_CONFIGURED,

 USB_STATE_SUSPENDED

};

#endif
