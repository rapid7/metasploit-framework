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
#ifndef _PLATFORM_DEVICE_H_
#define _PLATFORM_DEVICE_H_

#include <linux/device.h>

struct platform_device {
 const char * name;
 u32 id;
 struct device dev;
 u32 num_resources;
 struct resource * resource;
};

#define to_platform_device(x) container_of((x), struct platform_device, dev)

struct platform_driver {
 int (*probe)(struct platform_device *);
 int (*remove)(struct platform_device *);
 void (*shutdown)(struct platform_device *);
 int (*suspend)(struct platform_device *, pm_message_t state);
 int (*resume)(struct platform_device *);
 struct device_driver driver;
};

#define platform_get_drvdata(_dev) dev_get_drvdata(&(_dev)->dev)
#define platform_set_drvdata(_dev,data) dev_set_drvdata(&(_dev)->dev, (data))

#endif
