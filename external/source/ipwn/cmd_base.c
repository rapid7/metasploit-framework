/*
 * Copyright (c) 2004-2005 vlad902 <vlad902 [at] gmail.com>
 * Copyright (c) 2007 H D Moore <hdm [at] metasploit.com>
 * This file is part of the Metasploit Framework.
 * $Revision$
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#include "cmd.h"


void cmd_help(int argc, char * argv[])
{
	printf(	"Available commands:\n"
		"    help                            Show this help screen\n"
		"    fork                            Fork off another shelldemo process\n"
		"    exec <cmd>                      Execute <cmd>\n"
		"    system <cmd>                    Fork and execute <cmd> on std(in/out/err)\n"
		"    quit                            Exit the shell\n"
		
		"\n"
		"    open <path>                     Open a file and return the file descriptor\n"
		"    lseek <fd> <offset> <whence>    Reposition <fd>\n"
		"    read <fd> [bytes]               Read <bytes> from file descriptor\n"
		"    write <fd> [bytes]              Write [bytes] (or until \"EOF\") to <fd>\n"
		"    close <fd>                      Close specified file descriptor\n"
		"    dup <old_fd>                    Duplicate <old_fd> and return new reference\n"
		"    dup2 <old_fd> <new_fd>          Duplicate <old_fd> to <new_fd>\n"
		
		"\n"
		"    ls [path]                       Print information/contents about [path] (default: .)\n"
		"    getcwd                          Get current working directory\n"
		"    pwd                             Get current working directory\n"
		"    cd                              Set current working directory\n"		
		"    chmod <permission> <path>       Change <path> permissions to <permission>\n"
		"    chown <user> <path>             Change <path> owner to <user>\n"
		"    chgrp <group> <path>            Change <path> group to <group>\n"
		"    chdir <path>                    Change working directory to <path>\n"
		"    mkdir <path> [permission]       Create <path> directory with [permission] (default: 755)\n"
		"    rmdir <path>                    Remove <path> directory\n"
		"    rename <old_file> <new_file>    Rename <old_file> to <new_file>\n"
		"    unlink <path>                   Remove <path> file\n"
		"    chroot <path>                   Change root directory to <path>\n"
		"    link <file> <reference>         Hard link <reference> to <file>\n"
		"    symlink <file> <reference>      Symbolically link <reference> to <file>\n"
		"    cp <file> <file>                Copy a file from one directory to another\n"
		
		"\n"
		"    getid                           Print information about [e][ug]id\n"
		"    setuid <uid>                    Set UID to <uid>\n"
		"    setgid <gid>                    Set GID to <gid>\n"
		
		"\n"
		"    kill <pid> [signal]             Send <pid> [signal] (default: 9)\n"
		"    getpid                          Print current process ID\n"
		"    getppid                         Print parent process ID\n"
		"    ps                              Print process list\n"
		
		"\n"
		"    time                            Display the current system time\n"
		"    uname                           Get kernel information\n"
		"    hostname [name]                 Print (or set) the hostname\n"
		"    reboot                          Reboot the computer\n"
		"    shutdown                        Shutdown the computer\n"
		"    halt                            Halt the computer\n"
		
		"\n"
		"    lsfd                            Show information about open file descriptors\n"
		
		"\n"
		"    download <url> <file>           Download a file to disk over HTTP\n"
		
		"\n"
		"Warning! Before using any of the following you are recommended to fork for your own safety!\n"
		"    fchdir_breakchroot <temp_dir>   Use <temp_dir> to attempt to break out of chroot\n");
}


/* XXX: sig_chld stuff is dirty, get rid of it */
void cmd_fork(int argc, char * argv[])
{
	pid_t fork_pid;
	
	signal(SIGCHLD, &sig_chld_ignore);
	if((fork_pid = fork()) != 0)
	{
		while(waitpid(fork_pid, NULL, WNOHANG) <= 0)
			usleep(300);
	}
	signal(SIGCHLD, &sig_chld_waitpid);
}

void cmd_exec(int argc, char * argv[])
{
	int i;
	char *prog;
	
	argv++;
	
	prog = argv[0];
	
	printf("Executing");
	for(i=0; argv[i]; i++) {
		printf(" %s", argv[i]);	
	}
	printf("\n");
	
	execve(prog, argv, NULL);
	perror("execve");
}

void cmd_system(int argc, char * argv[])
{
	pid_t fork_pid;
	
	signal(SIGCHLD, &sig_chld_ignore);
	if((fork_pid = fork()) != 0)
	{
		while(waitpid(fork_pid, NULL, WNOHANG) <= 0)
			usleep(300);
	} else {
		cmd_exec(argc, argv);
		exit(0);
	}
	signal(SIGCHLD, &sig_chld_waitpid);
}

void cmd_quit(int argc, char * argv[])
{
	exit(0);
}


void cmd_script(int argc, char * argv[])
{
	FILE *fd;
	char buff[2048];
	
	fd = fopen(argv[1], "r");
	if (fd == NULL) {
		perror("fopen");
		return;
	}
	
	printf("Executing script %s\n", argv[1]);
	while (fgets(buff, sizeof(buff), fd)) {
		chomp(buff);
		process_input(buff, sizeof(buff));
	}
	
	fclose(fd);
}

