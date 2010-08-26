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
#ifndef LINUX_MOD_DEVICETABLE_H
#define LINUX_MOD_DEVICETABLE_H

#define PCI_ANY_ID (~0)

struct pci_device_id {
 __u32 vendor, device;
 __u32 subvendor, subdevice;
 __u32 class, class_mask;
 kernel_ulong_t driver_data;
};

#define IEEE1394_MATCH_VENDOR_ID 0x0001
#define IEEE1394_MATCH_MODEL_ID 0x0002
#define IEEE1394_MATCH_SPECIFIER_ID 0x0004
#define IEEE1394_MATCH_VERSION 0x0008

struct ieee1394_device_id {
 __u32 match_flags;
 __u32 vendor_id;
 __u32 model_id;
 __u32 specifier_id;
 __u32 version;
 kernel_ulong_t driver_data
 __attribute__((aligned(sizeof(kernel_ulong_t))));
};

struct usb_device_id {

 __u16 match_flags;

 __u16 idVendor;
 __u16 idProduct;
 __u16 bcdDevice_lo;
 __u16 bcdDevice_hi;

 __u8 bDeviceClass;
 __u8 bDeviceSubClass;
 __u8 bDeviceProtocol;

 __u8 bInterfaceClass;
 __u8 bInterfaceSubClass;
 __u8 bInterfaceProtocol;

 kernel_ulong_t driver_info;
};

#define USB_DEVICE_ID_MATCH_VENDOR 0x0001
#define USB_DEVICE_ID_MATCH_PRODUCT 0x0002
#define USB_DEVICE_ID_MATCH_DEV_LO 0x0004
#define USB_DEVICE_ID_MATCH_DEV_HI 0x0008
#define USB_DEVICE_ID_MATCH_DEV_CLASS 0x0010
#define USB_DEVICE_ID_MATCH_DEV_SUBCLASS 0x0020
#define USB_DEVICE_ID_MATCH_DEV_PROTOCOL 0x0040
#define USB_DEVICE_ID_MATCH_INT_CLASS 0x0080
#define USB_DEVICE_ID_MATCH_INT_SUBCLASS 0x0100
#define USB_DEVICE_ID_MATCH_INT_PROTOCOL 0x0200

struct ccw_device_id {
 __u16 match_flags;

 __u16 cu_type;
 __u16 dev_type;
 __u8 cu_model;
 __u8 dev_model;

 kernel_ulong_t driver_info;
};

#define CCW_DEVICE_ID_MATCH_CU_TYPE 0x01
#define CCW_DEVICE_ID_MATCH_CU_MODEL 0x02
#define CCW_DEVICE_ID_MATCH_DEVICE_TYPE 0x04
#define CCW_DEVICE_ID_MATCH_DEVICE_MODEL 0x08

#define PNP_ID_LEN 8
#define PNP_MAX_DEVICES 8

struct pnp_device_id {
 __u8 id[PNP_ID_LEN];
 kernel_ulong_t driver_data;
};

struct pnp_card_device_id {
 __u8 id[PNP_ID_LEN];
 kernel_ulong_t driver_data;
 struct {
 __u8 id[PNP_ID_LEN];
 } devs[PNP_MAX_DEVICES];
};

#define SERIO_ANY 0xff

struct serio_device_id {
 __u8 type;
 __u8 extra;
 __u8 id;
 __u8 proto;
};

struct of_device_id
{
 char name[32];
 char type[32];
 char compatible[128];
 kernel_ulong_t data;
};

struct vio_device_id {
 char type[32];
 char compat[32];
};

struct pcmcia_device_id {
 __u16 match_flags;

 __u16 manf_id;
 __u16 card_id;

 __u8 func_id;

 __u8 function;

 __u8 device_no;

 __u32 prod_id_hash[4]
 __attribute__((aligned(sizeof(__u32))));

 kernel_ulong_t prod_id[4]
 __attribute__((aligned(sizeof(kernel_ulong_t))));

 kernel_ulong_t driver_info;
 kernel_ulong_t cisfile;
};

#define PCMCIA_DEV_ID_MATCH_MANF_ID 0x0001
#define PCMCIA_DEV_ID_MATCH_CARD_ID 0x0002
#define PCMCIA_DEV_ID_MATCH_FUNC_ID 0x0004
#define PCMCIA_DEV_ID_MATCH_FUNCTION 0x0008
#define PCMCIA_DEV_ID_MATCH_PROD_ID1 0x0010
#define PCMCIA_DEV_ID_MATCH_PROD_ID2 0x0020
#define PCMCIA_DEV_ID_MATCH_PROD_ID3 0x0040
#define PCMCIA_DEV_ID_MATCH_PROD_ID4 0x0080
#define PCMCIA_DEV_ID_MATCH_DEVICE_NO 0x0100
#define PCMCIA_DEV_ID_MATCH_FAKE_CIS 0x0200
#define PCMCIA_DEV_ID_MATCH_ANONYMOUS 0x0400

struct i2c_device_id {
 __u16 id;
};

#define INPUT_DEVICE_ID_EV_MAX 0x1f
#define INPUT_DEVICE_ID_KEY_MAX 0x1ff
#define INPUT_DEVICE_ID_REL_MAX 0x0f
#define INPUT_DEVICE_ID_ABS_MAX 0x3f
#define INPUT_DEVICE_ID_MSC_MAX 0x07
#define INPUT_DEVICE_ID_LED_MAX 0x0f
#define INPUT_DEVICE_ID_SND_MAX 0x07
#define INPUT_DEVICE_ID_FF_MAX 0x7f
#define INPUT_DEVICE_ID_SW_MAX 0x0f

#define INPUT_DEVICE_ID_MATCH_BUS 1
#define INPUT_DEVICE_ID_MATCH_VENDOR 2
#define INPUT_DEVICE_ID_MATCH_PRODUCT 4
#define INPUT_DEVICE_ID_MATCH_VERSION 8

#define INPUT_DEVICE_ID_MATCH_EVBIT 0x0010
#define INPUT_DEVICE_ID_MATCH_KEYBIT 0x0020
#define INPUT_DEVICE_ID_MATCH_RELBIT 0x0040
#define INPUT_DEVICE_ID_MATCH_ABSBIT 0x0080
#define INPUT_DEVICE_ID_MATCH_MSCIT 0x0100
#define INPUT_DEVICE_ID_MATCH_LEDBIT 0x0200
#define INPUT_DEVICE_ID_MATCH_SNDBIT 0x0400
#define INPUT_DEVICE_ID_MATCH_FFBIT 0x0800
#define INPUT_DEVICE_ID_MATCH_SWBIT 0x1000

struct input_device_id {

 kernel_ulong_t flags;

 __u16 bustype;
 __u16 vendor;
 __u16 product;
 __u16 version;

 kernel_ulong_t evbit[INPUT_DEVICE_ID_EV_MAX / BITS_PER_LONG + 1];
 kernel_ulong_t keybit[INPUT_DEVICE_ID_KEY_MAX / BITS_PER_LONG + 1];
 kernel_ulong_t relbit[INPUT_DEVICE_ID_REL_MAX / BITS_PER_LONG + 1];
 kernel_ulong_t absbit[INPUT_DEVICE_ID_ABS_MAX / BITS_PER_LONG + 1];
 kernel_ulong_t mscbit[INPUT_DEVICE_ID_MSC_MAX / BITS_PER_LONG + 1];
 kernel_ulong_t ledbit[INPUT_DEVICE_ID_LED_MAX / BITS_PER_LONG + 1];
 kernel_ulong_t sndbit[INPUT_DEVICE_ID_SND_MAX / BITS_PER_LONG + 1];
 kernel_ulong_t ffbit[INPUT_DEVICE_ID_FF_MAX / BITS_PER_LONG + 1];
 kernel_ulong_t swbit[INPUT_DEVICE_ID_SW_MAX / BITS_PER_LONG + 1];

 kernel_ulong_t driver_info;
};

#endif
