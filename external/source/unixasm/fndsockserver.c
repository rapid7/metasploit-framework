/*
 *  fndsockserver.c
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
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/select.h>
#include <unistd.h>
#include <errno.h>

#define BACKLOG 5

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

	if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	if (listen(s, BACKLOG) == -1) {
		perror("listen");
		exit(EXIT_FAILURE);
	}

	if (debug || verbose)
		printf("listening on %s:%d\n", addr, port);

	while (1) {
		int tmp;
		struct sockaddr_in sin;
		socklen_t sin_len = sizeof(sin);

		if((tmp = accept(s, (struct sockaddr *)&sin, &sin_len)) == -1) {
			perror("accept");
			exit(EXIT_FAILURE);
		}

		if (debug || verbose)
			printf("accepted connection from %s:%d\n", inet_ntoa(sin.sin_addr),
			ntohs(sin.sin_port));

		if (!fork()) {
			int count;
			char buf[1024];

			count = recv(tmp, buf, sizeof(buf), 0);

			if (debug)
				hexdump(buf, count);

			if (debug || verbose)
				printf("%d bytes received\n", count);

			sleep(2);

#if defined(_AIX) || (defined(__linux__) && defined(__powerpc64__))
			{
				/* fake function descriptor */
				unsigned long fdesc[2] = {(unsigned long)buf, 0};
				(*(void (*)())fdesc)();
			}
#else
			(*(void (*)())buf)();
#endif

			exit(EXIT_SUCCESS);
		}
	}

	exit(EXIT_SUCCESS);
}

