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
#include <pwd.h>
#include <grp.h>

#include "cmd.h"


void cmd_getid(int argc, char * argv[])
{
	struct passwd * pwd;
	struct group * grp;

	printf("uid=%u", getuid());
	if((pwd = getpwuid(getuid())) != NULL)
		printf("(%s)", pwd->pw_name);

	printf(" gid=%u", getgid());
	if((grp = getgrgid(getgid())) != NULL)
		printf("(%s)", grp->gr_name);

	if(geteuid() != getuid())
	{
		printf(" euid=%u", geteuid());
		if((pwd = getpwuid(geteuid())) != NULL)
			printf("(%s)", pwd->pw_name);
	}
	if(getegid() != getgid())
	{
		printf(" egid=%u", getegid());
		if((grp = getgrgid(getegid())) != NULL)
			printf("(%s)", grp->gr_name);
	}

	printf("\n");
}

void cmd_setuid(int argc, char * argv[])
{
	if(setuid(atoi(argv[1])) == -1)
		perror("setuid");
}

void cmd_setgid(int argc, char * argv[])
{
	if(setgid(atoi(argv[1])) == -1)
		perror("setgid");
}
