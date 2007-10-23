/*
 * Copyright (c) 2004-2005 vlad902 <vlad902 [at] gmail.com>
 * Copyright (c) 2007 H D Moore <hdm [at] metasploit.com>  
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
#include <fcntl.h>

#include "cmd.h"


void cmd_open(int argc, char * argv[])
{
	int fd;

	fd = open(argv[1], O_RDWR | O_CREAT | O_APPEND, S_IRWXU);
	if(fd == -1)
		fd = open(argv[1], O_RDONLY);

	if(fd == -1)
		perror("open");
	else
		printf("open: %d\n", fd);
}

void cmd_lseek(int argc, char * argv[])
{
	int fd, offset, whence;
	int ret;

	fd = atoi(argv[1]);
	offset = atoi(argv[2]);
	whence = -1;

	if(strcasecmp(argv[3], "SEEK_SET") == 0)
		whence = SEEK_SET;
	if(strcasecmp(argv[3], "SEEK_CUR") == 0)
		whence = SEEK_CUR;
	if(strcasecmp(argv[3], "SEEK_END") == 0)
		whence = SEEK_END;

	if(whence == -1)
	{
		printf("whence was not SEEK_SET, SEEK_CUR, or SEEK_END\n");
		return;
	}

	if((ret = lseek(fd, offset, whence)) == -1)
		perror("lseek");
	else
		printf("lseek: %i\n", ret);
}

void cmd_read(int argc, char * argv[])
{
	int fd, size;
	int read_out, rsz;
	char buf[512];

	fd = atoi(argv[1]);
	{ /* Get max length to read... ugly. */
		int cur, end;

		cur = lseek(fd, 0, SEEK_CUR);
		end = lseek(fd, 0, SEEK_END);

		size = end - cur;
		lseek(fd, cur, SEEK_SET);
	}
	if(argc > 2)
		size = atoi(argv[2]);

	for(rsz = 0; rsz < size;)
	{
		read_out = read(fd, buf, __MIN_NUM(sizeof(buf), size - rsz));
		if(read_out == -1)
			return;
		write(1, buf, read_out);
		rsz += read_out;
	}
}

void cmd_write(int argc, char * argv[])
{
	int fd, size = -1;
	int read_in, rsz;
	char buf[512];

	fd = atoi(argv[1]);
	if(argc > 2)
		size = atoi(argv[2]);

	for(rsz = 0; rsz < size || size == -1;)
	{
		if(size != -1)
			read_in = read(1, buf, __MIN_NUM(sizeof(buf), size - rsz));
		else
			read_in = read(1, buf, sizeof(buf));

		if(read_in == -1)
				return;

		if(size == -1 && read_in >= 3)
		{
			char local[sizeof(buf)];

			memcpy(local, buf, sizeof(buf));
			if(local[read_in - 1] == '\n')
				local[read_in - 1] = '\0'; 
			if(local[read_in - 1] == '\r')
				local[read_in - 1] = '\0'; 

			if(strcmp(local, "EOF") == 0)
				return;
		}

		write(fd, buf, read_in);
		rsz += read_in;
	}
}

void cmd_close(int argc, char * argv[])
{
	if(close(atoi(argv[1])) == -1)
		perror("close");
}

void cmd_dup(int argc, char * argv[])
{
	int new_fd;

	if((new_fd = dup(atoi(argv[1]))) == -1)
		perror("dup");

	printf("%i\n", new_fd);
}

void cmd_dup2(int argc, char * argv[])
{
	if(dup2(atoi(argv[1]), atoi(argv[2])) == -1)
		perror("dup2");
}
