/*
 * Copyright (c) 2004-2005 vlad902 <vlad902 [at] gmail.com>
 * Copyright (c) 2007 H D Moore <hdm [at] metasploit.com> 
 * This file is part of the Metasploit Framework.
 * $Revision$
 */

#ifndef _CMD_H
#define	_CMD_H

	/* Base */
	int process_input(char *, int);
	void parse(char *, int *, char * []);
	void chomp(char *);
	
	void cmd_script(int, char * []);
	
	/* XXX: Re-do help to specify a category and print the commands in that category? */
	void cmd_help(int, char * []);
	void cmd_fork(int, char * []);
	void cmd_exec(int, char * []);
	void cmd_system(int, char * []);
	void cmd_quit(int, char * []);

	/* File descriptor handling */
	/* XXX: Take arg for perms (like lseek), O_EXCL?? */
	void cmd_open(int, char * []);
	void cmd_lseek(int, char * []);
	void cmd_read(int, char * []);
	void cmd_write(int, char * []);
	void cmd_close(int, char * []);
	void cmd_dup(int, char * []);
	void cmd_dup2(int, char * []);

	/* File system */
	/* XXX: copy, mount/unmount, showmount */
	void cmd_ls(int, char * []);
	void cmd_getcwd(int, char * []);
	void cmd_setcwd(int, char * []);
	void cmd_chmod(int, char * []);
	void cmd_chown(int, char * []);
	void cmd_chgrp(int, char * []);
	void cmd_chdir(int, char * []);
	void cmd_mkdir(int, char * []);
	void cmd_rmdir(int, char * []);
	void cmd_rename(int, char * []);
	void cmd_unlink(int, char * []);
	void cmd_chroot(int, char * []);
	void cmd_link(int, char * []);
	void cmd_symlink(int, char * []);
	void cmd_cp(int, char * []);
	
	/* Privileges */
	/* XXX: Print groups */
	void cmd_getid(int, char * []);
	void cmd_setuid(int, char * []);
	void cmd_setgid(int, char * []);

	/* Process */
	/* XXX: ps */
	void cmd_kill(int, char * []);
	void cmd_getpid(int, char * []);
	void cmd_getppid(int, char * []);
	void cmd_ps(int, char * []);
	
	/* Environment */
	/* XXX: setenv, showenv */

	/* System */
	/* XXX: dmesg, getrlimit */
	void cmd_time(int, char * []);
	void cmd_uname(int, char * []);
	void cmd_hostname(int, char * []);
	void cmd_reboot(int, char * []);
	void cmd_shutdown(int, char * []);
	void cmd_halt(int, char * []);

	/* Network */
	void cmd_download(int, char * []);
	
	/* Misc. */
	void cmd_lsfd(int, char * []);

	/* Exploit */
	void cmd_fchdir_breakchroot(int, char * []);



	#define	__MIN_NUM(a, b)		((a) < (b) ? (a) : (b))
	#define	__MAX_NUM(a, b)		((a) > (b) ? (a) : (b))

	char * get_uid_str(int);
	char * get_gid_str(int);
	char * get_time_str(char *);

	void sig_chld_ignore(int);
	void sig_chld_waitpid(int);
#endif /* _CMD_H */
