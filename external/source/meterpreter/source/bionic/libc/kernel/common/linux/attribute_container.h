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
#ifndef _ATTRIBUTE_CONTAINER_H_
#define _ATTRIBUTE_CONTAINER_H_

#include <linux/device.h>
#include <linux/list.h>
#include <linux/klist.h>
#include <linux/spinlock.h>

struct attribute_container {
 struct list_head node;
 struct klist containers;
 struct class *class;
 struct class_device_attribute **attrs;
 int (*match)(struct attribute_container *, struct device *);
#define ATTRIBUTE_CONTAINER_NO_CLASSDEVS 0x01
 unsigned long flags;
};

struct attribute_container *attribute_container_classdev_to_container(struct class_device *);
struct class_device *attribute_container_find_class_device(struct attribute_container *, struct device *);
struct class_device_attribute **attribute_container_classdev_to_attrs(const struct class_device *classdev);

#endif
