/*
 * Copyright (c) 2004-2005 vlad902 <vlad902 [at] gmail.com>
 * This file is part of the Metasploit Framework.
 * $Revision$
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#include "cmd.h"


/* Taken from solar eclipse's vuln.c */
void cmd_lsfd(int argc, char * argv[])
{
	int fd;

	for(fd=0; fd <= 1024; fd++)
	{
		struct stat st;
		char perm[10] = "---------";

		if (fstat(fd, &st) == 0)
		{
			char *type, *p;
			char extra[1024];

			memset(extra, 0, sizeof(extra));

			if(S_ISREG(st.st_mode))
				type = "file";

			if(S_ISDIR(st.st_mode))
				type = "directory";

			if(S_ISCHR(st.st_mode))
			{
				type = "character";
				p = ttyname(fd);
				if (p != NULL)
					strncpy(extra, p, sizeof(extra));
			}

			if(S_ISBLK(st.st_mode))
				type = "block";

			if(S_ISFIFO(st.st_mode))
				type = "fifo";

			if(S_ISLNK(st.st_mode))
				type = "symlink";
            
			if(S_ISSOCK(st.st_mode))
			{
				char locip[16], remip[16];
				struct sockaddr_in loc, rem;
				unsigned int slen = sizeof(struct sockaddr);

				memset(locip, 0, sizeof(locip));
				memset(remip, 0, sizeof(remip));

				getsockname(fd, (struct sockaddr *)&loc, &slen);
				getpeername(fd, (struct sockaddr *)&rem, &slen);

				strncpy(locip, (char *) inet_ntoa(loc.sin_addr), sizeof(locip));
				strncpy(remip, (char *) inet_ntoa(rem.sin_addr), sizeof(remip));

				snprintf(extra, sizeof(extra), "%s:%u -> %s:%u", 
					locip, ntohs(loc.sin_port), 
					remip, ntohs(rem.sin_port));

				type = "socket";
			}

			if(st.st_mode & S_IRUSR) perm[0] = 'r';
			if(st.st_mode & S_IWUSR) perm[1] = 'w';
			if(st.st_mode & S_IXUSR) perm[2] = 'x';
			if(st.st_mode & S_IRGRP) perm[3] = 'r';
			if(st.st_mode & S_IWGRP) perm[4] = 'w';
			if(st.st_mode & S_IXGRP) perm[5] = 'x';
			if(st.st_mode & S_IROTH) perm[6] = 'r';
			if(st.st_mode & S_IWOTH) perm[7] = 'w';
			if(st.st_mode & S_IXOTH) perm[8] = 'x';

			printf("[%d] [%s] dev=%d ino=%d uid=%d gid=%d rdev=%d size=%d %s (%s)\n",
				fd,
				perm,
				(int)st.st_dev,
				(int)st.st_ino,
				st.st_uid,
				st.st_gid,
				(int)st.st_rdev,
				(int)st.st_size,
				type,
				extra);
		}
	}
}
