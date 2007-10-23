/*
 * Copyright (c) 2004-2005 vlad902 <vlad902 [at] gmail.com>
 * Copyright (c) 2007 H D Moore <hdm [at] metasploit.com>  
 * This file is part of the Metasploit Framework.
 * $Revision$
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <sys/fcntl.h>

#include "cmd.h"


void ls_dofile(struct stat, char *);

void cmd_ls(int argc, char * argv[])
{
	char * path = ".";
	DIR * dirp;
	struct dirent * dp;
	struct stat sb;
	
	if(argc > 1)
		path = argv[1];
	
	if(stat(path, &sb) == -1)
	{
		perror("stat");
		return;
	}
	
	if(!S_ISDIR(sb.st_mode))
	{
		ls_dofile(sb, path);
	}
	else
	{
		if((dirp = opendir(path)) == NULL)
		{
			perror("opendir");
			return;
		}
		
		while((dp = readdir(dirp)) != NULL)
		{
			char buf[MAXPATHLEN+1];
			
			if(strlen(path) + strlen(dp->d_name) + 1 > MAXPATHLEN)
				continue;
			snprintf(buf, MAXPATHLEN, "%s/%s", path, dp->d_name);
			if(stat(buf, &sb) == -1)
				continue;
		
			ls_dofile(sb, dp->d_name);
		}
	}
}

void ls_dofile(struct stat sb, char * file_name)
{
	char perm[11] = "----------";
	
	if(sb.st_mode & 0400) perm[1] = 'r';
	if(sb.st_mode & 0200) perm[2] = 'w';
	if(sb.st_mode & 0100) perm[3] = 'x';
	if(sb.st_mode & 0040) perm[4] = 'r';
	if(sb.st_mode & 0020) perm[5] = 'w';
	if(sb.st_mode & 0010) perm[6] = 'x';
	if(sb.st_mode & 0004) perm[7] = 'r';
	if(sb.st_mode & 0002) perm[8] = 'w';
	if(sb.st_mode & 0001) perm[9] = 'x';
	if(sb.st_mode & S_ISVTX)
	{
		if(sb.st_mode & 0001)
			perm[9] = 't';
		else
			perm[9] = 'T';
	}
	if(sb.st_mode & S_ISGID)
	{
		if(sb.st_mode & 0010)
			perm[6] = 'S';
		else
			perm[6] = 's';
	}
	if(sb.st_mode & S_ISUID)
	{
		if(sb.st_mode & 0100)
			perm[3] = 'S';
		else
			perm[3] = 's';
	}
	if(S_ISBLK(sb.st_mode)) perm[0] = 'b';
	if(S_ISCHR(sb.st_mode)) perm[0] = 'c';
	if(S_ISDIR(sb.st_mode)) perm[0] = 'd';
	if(S_ISLNK(sb.st_mode)) perm[0] = 'l'; /* XXX: works? */
	if(S_ISFIFO(sb.st_mode)) perm[0] = 'p';
	if(S_ISSOCK(sb.st_mode)) perm[0] = 's';

	printf("%s %3i %s %s %6i %s %s\n", perm, (int)sb.st_nlink, \
		get_uid_str(sb.st_uid), get_gid_str(sb.st_gid), \
		(int)sb.st_size, get_time_str("%b %d %H:%M"), file_name);
}

void cmd_getcwd(int argc, char * argv[])
{
/* This should be big enough to accomodate all cases. */
	char buf[MAXPATHLEN + 1];

	if(getcwd(buf, sizeof(buf)) == NULL)
		perror("getcwd");
	else
		printf("%s\n", buf);
}

void cmd_setcwd(int argc, char * argv[])
{
	if(argc < 2)
		cmd_getcwd(argc, argv);
	else
		if(chdir(argv[1]))
			perror("chdir");
}


void cmd_chmod(int argc, char * argv[])
{
	int perm;

	errno = 0;
	perm = (int)strtol(argv[1], (char **)NULL, 8);
	if(errno)
	{
		perror("strtol");
		return;
	}

	if(chmod(argv[2], perm) == -1)
		perror("chmod");
}

void cmd_chown(int argc, char * argv[])
{
	struct passwd * pwd;
	int uid;

	errno = 0;
	uid = (int)strtol(argv[1], (char **)NULL, 10);
	if(errno)
	{
		if((pwd = getpwnam(argv[1])) == NULL)
		{
			perror("getpwnam");
			return;
		}

		uid = pwd->pw_uid;
	}

	if(chown(argv[2], uid, -1) == -1)
		perror("chown");
}

void cmd_chgrp(int argc, char * argv[])
{
	struct group * grp;
	int gid;

	errno = 0;
	gid = (int)strtol(argv[1], (char **)NULL, 10);
	if(errno)
	{
		if((grp = getgrnam(argv[1])) == NULL)
		{
			perror("getgrnam");
			return;
		}

		gid = grp->gr_gid;
	}

	if(chown(argv[2], -1, gid) == -1)
		perror("chown");
}

void cmd_chdir(int argc, char * argv[])
{
	if(chdir(argv[1]) == -1)
		perror("chdir");
}

void cmd_mkdir(int argc, char * argv[])
{
	int perm = 0755;

	if(argc > 2)
	{
		errno = 0;
		perm = (int)strtol(argv[2], (char **)NULL, 8);
		if(errno)
		{
			perror("strtol");
			return;
		}
	}

	if(mkdir(argv[1], perm) == -1)
		perror("mkdir");
}

void cmd_rmdir(int argc, char * argv[])
{
	if(rmdir(argv[1]) == -1)
		perror("rmdir");
}

void cmd_rename(int argc, char * argv[])
{
	if(rename(argv[1], argv[2]) == -1)
		perror("rename");
}

void cmd_unlink(int argc, char * argv[])
{
	if(unlink(argv[1]) == -1)
		perror("unlink");
}

void cmd_chroot(int argc, char * argv[])
{
	if(chroot(argv[1]) == -1)
		perror("chroot");
}

void cmd_link(int argc, char * argv[])
{
	if(link(argv[1], argv[2]) == -1)
		perror("link");
}

void cmd_symlink(int argc, char * argv[])
{
	if(symlink(argv[1], argv[2]) == -1)
		perror("symlink");
}

void cmd_cp(int argc, char * argv[])
{
	int src, dst, len;
	char buff[4096];
	struct stat s;
	char *path, *p, *t;
	
	path = strdup(argv[2]);
		
	src = open(argv[1], O_RDONLY);
	if(src == -1) {
		free(path);
		perror("open(src)");
	}
	
	dst = open(path, O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
	if (dst == -1) {
		
		if(errno == EISDIR)  {
			t = strrchr(argv[1], '/');
			if (t != NULL) {
				t++;
			} else {
				t = argv[1];
			}
			
			p = malloc(strlen(path) + strlen(t) + 2);
			sprintf(p, "%s/%s", path, t);
			free(path);
			path = p;

			dst = open(path, O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
			if ( dst == -1 ) {
				close(src);
				free(path);
				perror("open(dst)");				
			}
			
		} else {
			close(src);
			free(path);
			perror("open(dst)");
		}
	}
	
	stat(argv[1], &s);
	
	while(1) 
	{
		len = read(src, buff, sizeof(buff));
		if (len == -1) break;
		if (len ==  0) break;
		
		write(dst, buff, len);
		if (len < sizeof(buff)) break;
	}
	close(src);
	close(dst);
	
	chmod(path, s.st_mode);
	free(path);
}
