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
#ifndef _LINUX_MODULE_PARAMS_H
#define _LINUX_MODULE_PARAMS_H

#include <linux/init.h>
#include <linux/stringify.h>
#include <linux/kernel.h>

#ifdef MODULE
#define MODULE_PARAM_PREFIX  
#else
#define MODULE_PARAM_PREFIX KBUILD_MODNAME "."
#endif

#ifdef MODULE
#define ___module_cat(a,b) __mod_ ## a ## b
#define __module_cat(a,b) ___module_cat(a,b)
#define __MODULE_INFO(tag, name, info)  static const char __module_cat(name,__LINE__)[]   __attribute_used__   __attribute__((section(".modinfo"),unused)) = __stringify(tag) "=" info
#else
#define __MODULE_INFO(tag, name, info)
#endif
#define __MODULE_PARM_TYPE(name, _type)   __MODULE_INFO(parmtype, name##type, #name ":" _type)

struct kernel_param;

typedef int (*param_set_fn)(const char *val, struct kernel_param *kp);

typedef int (*param_get_fn)(char *buffer, struct kernel_param *kp);

struct kernel_param {
 const char *name;
 unsigned int perm;
 param_set_fn set;
 param_get_fn get;
 void *arg;
};

struct kparam_string {
 unsigned int maxlen;
 char *string;
};

struct kparam_array
{
 unsigned int max;
 unsigned int *num;
 param_set_fn set;
 param_get_fn get;
 unsigned int elemsize;
 void *elem;
};

#define __module_param_call(prefix, name, set, get, arg, perm)   static char __param_str_##name[] = prefix #name;   static struct kernel_param const __param_##name   __attribute_used__   __attribute__ ((unused,__section__ ("__param"),aligned(sizeof(void *))))   = { __param_str_##name, perm, set, get, arg }

#define module_param_call(name, set, get, arg, perm)   __module_param_call(MODULE_PARAM_PREFIX, name, set, get, arg, perm)

#define module_param_named(name, value, type, perm)   param_check_##type(name, &(value));   module_param_call(name, param_set_##type, param_get_##type, &value, perm);   __MODULE_PARM_TYPE(name, #type)

#define module_param(name, type, perm)   module_param_named(name, name, type, perm)

#define module_param_string(name, string, len, perm)   static struct kparam_string __param_string_##name   = { len, string };   module_param_call(name, param_set_copystring, param_get_string,   &__param_string_##name, perm);   __MODULE_PARM_TYPE(name, "string")

#define __param_check(name, p, type)   static inline type *__check_##name(void) { return(p); }

#define param_check_byte(name, p) __param_check(name, p, unsigned char)

#define param_check_short(name, p) __param_check(name, p, short)

#define param_check_ushort(name, p) __param_check(name, p, unsigned short)

#define param_check_int(name, p) __param_check(name, p, int)

#define param_check_uint(name, p) __param_check(name, p, unsigned int)

#define param_check_long(name, p) __param_check(name, p, long)

#define param_check_ulong(name, p) __param_check(name, p, unsigned long)

#define param_check_charp(name, p) __param_check(name, p, char *)

#define param_check_bool(name, p) __param_check(name, p, int)

#define param_check_invbool(name, p) __param_check(name, p, int)

#define module_param_array_named(name, array, type, nump, perm)   static struct kparam_array __param_arr_##name   = { ARRAY_SIZE(array), nump, param_set_##type, param_get_##type,  sizeof(array[0]), array };   module_param_call(name, param_array_set, param_array_get,   &__param_arr_##name, perm);   __MODULE_PARM_TYPE(name, "array of " #type)

#define module_param_array(name, type, nump, perm)   module_param_array_named(name, name, type, nump, perm)

struct module;

#endif
