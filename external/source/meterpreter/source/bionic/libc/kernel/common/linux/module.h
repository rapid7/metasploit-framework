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
#ifndef _LINUX_MODULE_H
#define _LINUX_MODULE_H

#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/stat.h>
#include <linux/compiler.h>
#include <linux/cache.h>
#include <linux/kmod.h>
#include <linux/elf.h>
#include <linux/stringify.h>
#include <linux/kobject.h>
#include <linux/moduleparam.h>
#include <asm/local.h>

#include <asm/module.h>

#define MODULE_SUPPORTED_DEVICE(name)

#ifndef MODULE_SYMBOL_PREFIX
#define MODULE_SYMBOL_PREFIX ""
#endif

#define MODULE_NAME_LEN (64 - sizeof(unsigned long))

struct kernel_symbol
{
 unsigned long value;
 const char *name;
};

struct modversion_info
{
 unsigned long crc;
 char name[MODULE_NAME_LEN];
};

struct module;

struct module_attribute {
 struct attribute attr;
 ssize_t (*show)(struct module_attribute *, struct module *, char *);
 ssize_t (*store)(struct module_attribute *, struct module *,
 const char *, size_t count);
 void (*setup)(struct module *, const char *);
 int (*test)(struct module *);
 void (*free)(struct module *);
};

struct module_kobject
{
 struct kobject kobj;
 struct module *mod;
};

struct exception_table_entry;

#ifdef MODULE
#define MODULE_GENERIC_TABLE(gtype,name)  extern const struct gtype##_id __mod_##gtype##_table   __attribute__ ((unused, alias(__stringify(name))))

#define THIS_MODULE (&__this_module)
#else
#define MODULE_GENERIC_TABLE(gtype,name)
#define THIS_MODULE ((struct module *)0)
#endif

#define MODULE_INFO(tag, info) __MODULE_INFO(tag, tag, info)

#define MODULE_ALIAS(_alias) MODULE_INFO(alias, _alias)

#define MODULE_LICENSE(_license) MODULE_INFO(license, _license)

#define MODULE_AUTHOR(_author) MODULE_INFO(author, _author)

#define MODULE_DESCRIPTION(_description) MODULE_INFO(description, _description)

#define MODULE_PARM_DESC(_parm, desc)   __MODULE_INFO(parm, _parm, #_parm ":" desc)

#define MODULE_DEVICE_TABLE(type,name)   MODULE_GENERIC_TABLE(type##_device,name)

#define MODULE_VERSION(_version) MODULE_INFO(version, _version)

struct notifier_block;

#define EXPORT_SYMBOL(sym)
#define EXPORT_SYMBOL_GPL(sym)
#define EXPORT_SYMBOL_GPL_FUTURE(sym)
#define EXPORT_UNUSED_SYMBOL(sym)
#define EXPORT_UNUSED_SYMBOL_GPL(sym)

#define symbol_get(x) ({ extern typeof(x) x __attribute__((weak)); &(x); })
#define symbol_put(x) do { } while(0)
#define symbol_put_addr(x) do { } while(0)
#define module_name(mod) "kernel"
#define __unsafe(mod)
#define module_put_and_exit(code) do_exit(code)

struct module;

#define symbol_request(x) try_then_request_module(symbol_get(x), "symbol:" #x)
#define __MODULE_STRING(x) __stringify(x)
#endif
