/*
 * exploit64.h - Get kernel_task, root and escape the sandbox
 *               Taken and modified from Phœnix Jailbreak
 *
 * Copyright (c) 2017 Siguza & tihmstar
 */

#ifndef EXPLOIT64_h
#define EXPLOIT64_h

#include <mach/mach.h>

task_t get_kernel_task(vm_address_t *kbase);

#endif
