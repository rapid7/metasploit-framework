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
#ifndef _DEVICE_H_
#define _DEVICE_H_

#include <linux/ioport.h>
#include <linux/kobject.h>
#include <linux/klist.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/pm.h>
#include <asm/semaphore.h>
#include <asm/atomic.h>

#define DEVICE_NAME_SIZE 50
#define DEVICE_NAME_HALF __stringify(20)  
#define DEVICE_ID_SIZE 32
#define BUS_ID_SIZE KOBJ_NAME_LEN

struct device;
struct device_driver;
struct class;
struct class_device;

struct bus_type {
 const char * name;

 struct subsystem subsys;
 struct kset drivers;
 struct kset devices;
 struct klist klist_devices;
 struct klist klist_drivers;

 struct bus_attribute * bus_attrs;
 struct device_attribute * dev_attrs;
 struct driver_attribute * drv_attrs;

 int (*match)(struct device * dev, struct device_driver * drv);
 int (*uevent)(struct device *dev, char **envp,
 int num_envp, char *buffer, int buffer_size);
 int (*probe)(struct device * dev);
 int (*remove)(struct device * dev);
 void (*shutdown)(struct device * dev);
 int (*suspend)(struct device * dev, pm_message_t state);
 int (*resume)(struct device * dev);
};

struct device * bus_find_device(struct bus_type *bus, struct device *start,
 void *data, int (*match)(struct device *, void *));

struct bus_attribute {
 struct attribute attr;
 ssize_t (*show)(struct bus_type *, char * buf);
 ssize_t (*store)(struct bus_type *, const char * buf, size_t count);
};

#define BUS_ATTR(_name,_mode,_show,_store)  struct bus_attribute bus_attr_##_name = __ATTR(_name,_mode,_show,_store)

struct device_driver {
 const char * name;
 struct bus_type * bus;

 struct completion unloaded;
 struct kobject kobj;
 struct klist klist_devices;
 struct klist_node knode_bus;

 struct module * owner;

 int (*probe) (struct device * dev);
 int (*remove) (struct device * dev);
 void (*shutdown) (struct device * dev);
 int (*suspend) (struct device * dev, pm_message_t state);
 int (*resume) (struct device * dev);
};

struct driver_attribute {
 struct attribute attr;
 ssize_t (*show)(struct device_driver *, char * buf);
 ssize_t (*store)(struct device_driver *, const char * buf, size_t count);
};

#define DRIVER_ATTR(_name,_mode,_show,_store)  struct driver_attribute driver_attr_##_name = __ATTR(_name,_mode,_show,_store)

struct device * driver_find_device(struct device_driver *drv,
 struct device *start, void *data,
 int (*match)(struct device *, void *));

struct class {
 const char * name;
 struct module * owner;

 struct subsystem subsys;
 struct list_head children;
 struct list_head devices;
 struct list_head interfaces;
 struct semaphore sem;

 struct class_attribute * class_attrs;
 struct class_device_attribute * class_dev_attrs;

 int (*uevent)(struct class_device *dev, char **envp,
 int num_envp, char *buffer, int buffer_size);

 void (*release)(struct class_device *dev);
 void (*class_release)(struct class *class);
};

struct class_attribute {
 struct attribute attr;
 ssize_t (*show)(struct class *, char * buf);
 ssize_t (*store)(struct class *, const char * buf, size_t count);
};

#define CLASS_ATTR(_name,_mode,_show,_store)  struct class_attribute class_attr_##_name = __ATTR(_name,_mode,_show,_store) 

struct class_device_attribute {
 struct attribute attr;
 ssize_t (*show)(struct class_device *, char * buf);
 ssize_t (*store)(struct class_device *, const char * buf, size_t count);
};

#define CLASS_DEVICE_ATTR(_name,_mode,_show,_store)  struct class_device_attribute class_device_attr_##_name =   __ATTR(_name,_mode,_show,_store)

struct class_device {
 struct list_head node;

 struct kobject kobj;
 struct class * class;
 dev_t devt;
 struct class_device_attribute *devt_attr;
 struct class_device_attribute uevent_attr;
 struct device * dev;
 void * class_data;
 struct class_device *parent;
 struct attribute_group ** groups;

 void (*release)(struct class_device *dev);
 int (*uevent)(struct class_device *dev, char **envp,
 int num_envp, char *buffer, int buffer_size);
 char class_id[BUS_ID_SIZE];
};

struct class_interface {
 struct list_head node;
 struct class *class;

 int (*add) (struct class_device *, struct class_interface *);
 void (*remove) (struct class_device *, struct class_interface *);
};

struct device_attribute {
 struct attribute attr;
 ssize_t (*show)(struct device *dev, struct device_attribute *attr,
 char *buf);
 ssize_t (*store)(struct device *dev, struct device_attribute *attr,
 const char *buf, size_t count);
};

#define DEVICE_ATTR(_name,_mode,_show,_store)  struct device_attribute dev_attr_##_name = __ATTR(_name,_mode,_show,_store)

struct device {
 struct klist klist_children;
 struct klist_node knode_parent;
 struct klist_node knode_driver;
 struct klist_node knode_bus;
 struct device * parent;

 struct kobject kobj;
 char bus_id[BUS_ID_SIZE];
 struct device_attribute uevent_attr;
 struct device_attribute *devt_attr;

 struct semaphore sem;

 struct bus_type * bus;
 struct device_driver *driver;
 void *driver_data;
 void *platform_data;
 void *firmware_data;
 struct dev_pm_info power;

 u64 *dma_mask;
 u64 coherent_dma_mask;

 struct list_head dma_pools;

 struct dma_coherent_mem *dma_mem;

 struct list_head node;
 struct class *class;
 dev_t devt;

 void (*release)(struct device * dev);
};

#define dev_printk(level, dev, format, arg...)   printk(level "%s %s: " format , dev_driver_string(dev) , (dev)->bus_id , ## arg)

#ifdef DEBUG
#define dev_dbg(dev, format, arg...)   dev_printk(KERN_DEBUG , dev , format , ## arg)
#else
#define dev_dbg(dev, format, arg...) do { (void)(dev); } while (0)
#endif

#define dev_err(dev, format, arg...)   dev_printk(KERN_ERR , dev , format , ## arg)
#define dev_info(dev, format, arg...)   dev_printk(KERN_INFO , dev , format , ## arg)
#define dev_warn(dev, format, arg...)   dev_printk(KERN_WARNING , dev , format , ## arg)
#define dev_notice(dev, format, arg...)   dev_printk(KERN_NOTICE , dev , format , ## arg)

#define MODULE_ALIAS_CHARDEV(major,minor)   MODULE_ALIAS("char-major-" __stringify(major) "-" __stringify(minor))
#define MODULE_ALIAS_CHARDEV_MAJOR(major)   MODULE_ALIAS("char-major-" __stringify(major) "-*")
#endif
