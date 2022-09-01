/*
 * find.h - Minimal offsets finder
 *          Taken and modified from cl0ver
 *
 * Copyright (c) 2016-2017 Siguza
 */

#ifndef FIND_H
#define FIND_H

#include <mach/mach.h>

#include "nvpatch.h"

vm_address_t find_kernel_task(segment_t *text);

vm_address_t find_ipc_space_kernel(segment_t *text);

#endif
