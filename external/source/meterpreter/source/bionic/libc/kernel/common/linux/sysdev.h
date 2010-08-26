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
#ifndef _SYSDEV_H_
#define _SYSDEV_H_

#include <linux/kobject.h>
#include <linux/pm.h>

struct sys_device;

struct sysdev_class {
 struct list_head drivers;

 int (*shutdown)(struct sys_device *);
 int (*suspend)(struct sys_device *, pm_message_t state);
 int (*resume)(struct sys_device *);
 struct kset kset;
};

struct sysdev_class_attribute {
 struct attribute attr;
 ssize_t (*show)(struct sysdev_class *, char *);
 ssize_t (*store)(struct sysdev_class *, const char *, size_t);
};

#define SYSDEV_CLASS_ATTR(_name,_mode,_show,_store)  struct sysdev_class_attribute attr_##_name = {   .attr = {.name = __stringify(_name), .mode = _mode },   .show = _show,   .store = _store,  };

struct sysdev_driver {
 struct list_head entry;
 int (*add)(struct sys_device *);
 int (*remove)(struct sys_device *);
 int (*shutdown)(struct sys_device *);
 int (*suspend)(struct sys_device *, pm_message_t state);
 int (*resume)(struct sys_device *);
};

struct sys_device {
 u32 id;
 struct sysdev_class * cls;
 struct kobject kobj;
};

struct sysdev_attribute {
 struct attribute attr;
 ssize_t (*show)(struct sys_device *, char *);
 ssize_t (*store)(struct sys_device *, const char *, size_t);
};

#define SYSDEV_ATTR(_name,_mode,_show,_store)  struct sysdev_attribute attr_##_name = {   .attr = {.name = __stringify(_name), .mode = _mode },   .show = _show,   .store = _store,  };

#endif
