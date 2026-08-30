#ifndef _KMEM_SEARCH_H_
#define _KMEM_SEARCH_H_

#include "exploit_configs.h"

#define KMEM_MAX_SEARCH 0xFFFFFFF

int search_init_pid_ns_kstrtab(exploit_context* pCtx);
int search_init_pid_ns_ksymtab(exploit_context* pCtx);
int find_pid_cred(exploit_context* pCtx, pid_t pid);

#endif