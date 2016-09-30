/*
 * Copyright (c) 2004-2005 vlad902 <vlad902 [at] gmail.com>
 * Copyright (c) 2007 H D Moore <hdm [at] metasploit.com>
 * This file is part of the Metasploit Framework.
 * $Revision$
 */


/* The process listing code was taken wholesale from the following file:
	http://www.psychofx.com/psi/trac/browser/psi/trunk/src/arch/macosx/macosx_processtable.c

This code was provided under the following license:

	The MIT License

	Copyright (c) 2007 Chris Miles

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in
	all copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
	THE SOFTWARE.
*/

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>

#include <sys/sysctl.h>
#include <sys/fcntl.h>
#include <sys/types.h>

#ifdef MACOSX
#include <sys/proc.h>
#include <mach/mach_traps.h>    /* for task_for_pid() */
#include <mach/shared_memory_server.h>
#include <mach/mach_init.h>
#include <mach/task.h>
#endif

#include "cmd.h"


void cmd_kill(int argc, char * argv[])
{
	int killsig = 9;

	if(argc > 1)
		killsig = atoi(argv[2]);

	if(kill(atoi(argv[1]), killsig) == -1)
		perror("kill");
}

void cmd_getpid(int argc, char * argv[])
{
	printf("%i\n", getpid());
}

void cmd_getppid(int argc, char * argv[])
{
	printf("%i\n", getppid());
}

void cmd_ps(int argc, char * argv[])
{
#ifdef MACOSX	
	int                 process_count;
	int                 err;
	int                 i;
	int                 done;
	size_t              length;
	static const int    name_getprocs[] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
	register struct kinfo_proc *p;
	struct kinfo_proc * result;

    // We start by calling sysctl with result == NULL and length == 0.
    // That will succeed, and set length to the appropriate length.
    // We then allocate a buffer of that size and call sysctl again
    // with that buffer.  If that succeeds, we're done.  If that fails
    // with ENOMEM, we have to throw away our buffer and loop.  Note
    // that the loop causes us to call sysctl with NULL again; this
    // is necessary because the ENOMEM failure case sets length to
    // the amount of data returned, not the amount of data that
    // could have been returned.
    
    result = NULL;
    done = 0;
    do {
        // Call sysctl with a NULL buffer.

        length = 0;
        err = sysctl( (int *) name_getprocs, (sizeof(name_getprocs) / sizeof(*name_getprocs)) - 1,
                      NULL, &length,
                      NULL, 0);
        if (err == -1) {
            err = errno;
        }

        // Allocate an appropriately sized buffer based on the results
        // from the previous call.

        if (err == 0) {
            result = malloc(length);
            if (result == NULL) {
                err = ENOMEM;
            }
        }

        // Call sysctl again with the new buffer.  If we get an ENOMEM
        // error, toss away our buffer and start again.

        if (err == 0) {
            err = sysctl( (int *) name_getprocs, (sizeof(name_getprocs) / sizeof(*name_getprocs)) - 1,
                          result, &length,
                          NULL, 0);
            if (err == -1) {
                err = errno;
            }
            if (err == 0) {
                done = 1;
            } else if (err == ENOMEM) {
                free(result);
                result = NULL;
                err = 0;
            }
        }
    } while (err == 0 && ! done);

    // Clean up and establish post conditions.

    if (err != 0 && result != NULL) {
        free(result);
        result = NULL;
    }
    
    if (err == 0) {
        process_count = length / sizeof(struct kinfo_proc);
    }

	printf("Process table:\n");    
    for(p = result, i = 0; i < process_count; p++, i++)
    {
		printf("%5d\t%s\n", p->kp_proc.p_pid, p->kp_proc.p_comm);
    }
#else
	printf("This command is not supported on this operating system.\n");
#endif	
}
