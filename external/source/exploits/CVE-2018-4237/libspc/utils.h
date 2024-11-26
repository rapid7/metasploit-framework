#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdio.h>
#include <stdlib.h>
#include <mach/mach.h>

#define ASSERT(c) if (!(c)) { printf("[-] assertion \"" #c "\" failed\n"); exit(-1); }
#define ASSERT_MSG(c, msg) if (!(c)) { printf("[-] %s\n", msg); exit(-1); }
#define ASSERT_SUCCESS(r, name) if (r != 0) { printf("[-] %s failed!\n", name); exit(-1); }
#define ASSERT_MACH_SUCCESS(r, name) if (r != 0) { printf("[-] %s failed: %s!\n", name, mach_error_string(r)); exit(-1); }
#define ASSERT_POSIX_SUCCESS(r, name) if (r != 0) { printf("[-] %s failed: %s!\n", name, strerror(r)); exit(-1); }

const char* spc_strerror(int errno);

int mach_port_addref(mach_port_t port, mach_port_right_t right);

#endif
