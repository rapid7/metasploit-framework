/*
 * Copyright (c) 2004-2005 vlad902 <vlad902 [at] gmail.com>
 * Copyright (c) 2007 H D Moore <hdm [at] metasploit.com> 
 * This file is part of the Metasploit Framework.
 * $Revision$
 */

#include <stdio.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include <string.h>

#include "cmd.h"


char * get_uid_str(int uid)
{
	struct passwd * pwd;
	static char id[20];

	snprintf(id, sizeof(id), "%i", uid);
	if((pwd = getpwuid(uid)) != NULL)
		strncpy(id, pwd->pw_name, sizeof(id));
	id[sizeof(id) - 1] = '\0';

	return id;
}

char * get_gid_str(int gid)
{
	struct group * grp;
	static char id[10];

	snprintf(id, sizeof(id), "%i", gid);
	if((grp = getgrgid(gid)) != NULL)
		strncpy(id, grp->gr_name, sizeof(id));
	id[sizeof(id) - 1] = '\0';

	return id;
}

char * get_time_str(char * format)
{
	static char time_stamp[128];
	time_t time_int;

	time(&time_int);
	strftime(time_stamp, sizeof(time_stamp), format, localtime(&time_int));
	return time_stamp;
}
