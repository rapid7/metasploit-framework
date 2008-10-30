//  Copyright (C) 1999 AT&T Laboratories Cambridge. All Rights Reserved.
//
//  This file is part of the VNC system.
//
//  The VNC system is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
//  USA.
//
// If the source code for the VNC system is not available from the place 
// whence you received this file, check http://www.uk.research.att.com/vnc or contact
// the authors on vnc@uk.research.att.com for information on obtaining it.


/*
 *  Functions for VNC password management and authentication.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <process.h>
#include "vncauth.h"
#include "d3des.h"

/*
 *   We use a fixed key to store passwords, since we assume that our local
 *   file system is secure but nonetheless don't want to store passwords
 *   as plaintext.
 */

unsigned char fixedkey[8] = {23,82,107,6,35,78,88,7};

/*
 *   Encrypt a password and store it in a file.
 */
int
vncEncryptPasswd(char *passwd, char *encryptedPasswd)
{
    int i;

    /* pad password with nulls */

    for (i = 0; i < MAXPWLEN; i++) {
	if (i < strlen(passwd)) {
	    encryptedPasswd[i] = passwd[i];
	} else {
	    encryptedPasswd[i] = 0;
	}
    }

    /* Do encryption in-place - this way we overwrite our copy of the plaintext
       password */

    deskey(fixedkey, EN0);
    des(encryptedPasswd, encryptedPasswd);

    return 8;
}

/*
 *   Decrypt a password.  Returns a pointer to a newly allocated
 *   string containing the password or a null pointer if the password could
 *   not be retrieved for some reason.
 */
char *
vncDecryptPasswd(char *inouttext)
{
    unsigned char *passwd = (unsigned char *)malloc(9);

    deskey(fixedkey, DE1);
    des(inouttext, passwd);

    passwd[8] = 0;

    return (char *)passwd;
}

/*
 *   Generate a set of random bytes for use in challenge-response authentication.
 */
void
vncRandomBytes(unsigned char *where) {
  int i;
  static unsigned int seed;
  seed += (unsigned int) time(0) + getpid() + getpid() * 987654;

  srand(seed);
  for (i=0; i < CHALLENGESIZE; i++) {
    where[i] = (unsigned char)(rand() & 255);    
  }
}

/*
 *   Encrypt some bytes in memory using a password.
 */
void
vncEncryptBytes(unsigned char *where, const char *passwd)
{
    unsigned char key[8];
    int i;

    /* key is simply password padded with nulls */

    for (i = 0; i < 8; i++) {
	if (i < strlen(passwd)) {
	    key[i] = passwd[i];
	} else {
	    key[i] = 0;
	}
    }

    deskey(key, EN0);

    for (i = 0; i < CHALLENGESIZE; i += 8) {
	des(where+i, where+i);
    }
}
