/*
 * mach-o.h - Code that deals with the Mach-O file format
 *            Taken from kern-utils
 *
 * Copyright (c) 2012 comex
 * Copyright (c) 2016 Siguza
 */

#ifndef MACH_O_H
#define MACH_O_H

#include <mach-o/loader.h>      // load_command

/*
 * Iterate over all load commands in a Mach-O header
 */
#define CMD_ITERATE(hdr, cmd) \
for(struct load_command *cmd = (struct load_command *) ((hdr) + 1), \
                        *end = (struct load_command *) ((char *) cmd + (hdr)->sizeofcmds); \
    cmd < end; \
    cmd = (struct load_command *) ((char *) cmd + cmd->cmdsize))

#endif
