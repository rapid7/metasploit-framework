/*
 * Copyright (c) 2004-2005 vlad902 <vlad902 [at] gmail.com>
 * This file is part of the Metasploit Framework.
 * $Revision$
 */

#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <sys/utsname.h>
#ifdef SYSCALL_REBOOT
#include <linux/reboot.h>

#define reboot(arg) reboot(0xfee1dead, 0x28121969, arg, NULL)
#else
#include <sys/reboot.h>
#endif

#include "cmd.h"


void cmd_time(int argc, char * argv[])
{
	printf("%s\n", get_time_str("%a %b %d %H:%M:%S %Z %Y"));
}

void cmd_uname(int argc, char * argv[])
{
	struct utsname info;

	if(uname(&info) == -1)
		perror("uname");
	else
		printf("%s %s %s %s %s\n", info.sysname, info.nodename, \
			info.release, info.version, info.machine);
}

void cmd_hostname(int argc, char * argv[])
{
/* This should be big enough to accomodate all cases. */
	char buf[8192];

	if(argc > 1)
	{
		if(sethostname(argv[1], strlen(argv[1])) == -1)
			perror("sethostname");
	}
	else
	{
		if(gethostname(buf, sizeof(buf)) == -1)
			perror("gethostname");
		else
			printf("%s\n", buf);
	}
}

void cmd_reboot(int argc, char * argv[])
{
	sync();

	if(reboot(0x01234567) == -1)
		perror("reboot");
}

/* Linux >= 2.1.30 */
void cmd_shutdown(int argc, char * argv[])
{
	sync();

	if(reboot(0x4321fedc) == -1)
		perror("shutdown");
}

/* Linux >= 1.1.76 */
void cmd_halt(int argc, char * argv[])
{
	sync();
	
	if(reboot(0xcdef0123) == -1)
		perror("halt");
}
