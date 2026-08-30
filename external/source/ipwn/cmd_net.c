/*
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
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "cmd.h"

void cmd_download(int argc, char * argv[])
{
	int src, dst, len, i;
	char buff[4096];
	char *path, *p, *t;
	char *uri;
	char *host;
	struct sockaddr_in server;
	struct hostent *haddr;
	int port  = 80;
	int dmode =  0;
	int off   =  0;
	int clen  =  0;
	int tot   =  0;
	
	// src == socket
	p = strstr(argv[1], "http://");
	if( p == NULL) {
		printf("The url must start with http://\n");
		return;
	}
	
	p+=7;
	
	t = strstr(p, "/");
	if (t == NULL) {
		printf("The url must contain a path\n");
		return;
	}
	
	uri = strdup(t);
	*t = '\0';
	
	t = strstr(p, ":");
	if (t != NULL) {
		*t = '\0';
		t++;
		port = atoi(t);
	}
	
	host = strdup(p);
	
	sprintf(buff, "GET %s HTTP/1.0\r\nHost: %s:%d\r\nConnection: Close\r\nUser-Agent: iPwn\r\n\r\n", uri, host, port);
	
	if( ( haddr = gethostbyname(host) ) == NULL ) {
		free(host);
		perror("gethostbyname");
		return;
	}
		
	free(host);

	if (port < 1 || port > 65535) {
		free(uri);
		perror("invalid port");
		return;
	}

  	if( ( src = socket ( PF_INET, SOCK_STREAM, IPPROTO_TCP ) ) < 0 ) {
		free(uri);		
		perror("socket");
		return;
	}

  	memset ( &server, 0, sizeof( server ) );
  	server.sin_family = AF_INET;
  	server.sin_addr.s_addr = *( ( unsigned long * ) haddr->h_addr );
  	server.sin_port = htons ( port );

  	if( connect ( src, ( struct sockaddr * )&server, sizeof( server ) ) < 0 ) {
		free(uri);		
		close(src);
		perror("connect");
		return;
	}

  	if( send( src, buff, strlen(buff), 0 ) != strlen(buff) ) {
		free(uri);		
		close(src);
		perror("send");
		return;
	}
		
	path = strdup(argv[2]);
	dst = open(path, O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
	if (dst == -1) {
		
		if(errno == EISDIR)  {
			t = strrchr(uri, '/');
			if (t != NULL) {
				t++;
				if(strlen(t) == 0) {
					free(uri);
					t = "download.out";
				}
			} else {
				t = uri;
			}
			
			p = malloc(strlen(path) + strlen(t) + 2);
			sprintf(p, "%s/%s", path, t);
			free(path);
			path = p;

			dst = open(path, O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
			if ( dst == -1 ) {
				close(src);
				free(path);
				free(uri);
				perror("open(dst)");
				return;
			}
			
		} else {
			close(src);
			free(path);
			free(uri);
			perror("open(dst)");
			return;
		}
	}

	free(uri);
	
	memset(buff, 0, sizeof(buff));	
	off = 0;
	tot = 0;
	while (dmode == 0) {
		
		if (sizeof(buff)-1-off <= 0)
			break;

		len = read(src, buff+off, sizeof(buff)-1-off);
		
		if (len == -1) break;
		if (len ==  0) break;
		off += len;
		
		p = strstr(buff, "Content-Length:");
		
		if (p) {
			p += 15;
			clen = atoi(p);
		}
		
		t = strstr(buff, "\r\n\r\n");		
		if (t) {		
			dmode = 1;
			*t = '\0';
			t += 4;

			i = (int) ((buff + off) - t);
			write(dst, t, i);
			tot += i;
		}
	}

	printf("\n====================\n");
	printf("HTTP Server Response\n");
	printf("====================\n\n%s\n\n",buff);
	
	if(! dmode || clen < 0) {
		printf("could not parse the server response\n");
		close(src);
		close(dst);
		unlink(path);
		free(path);
		return;
	}
	
	if(clen > 0) {
		printf("Receiving %d bytes...\n", clen);
		while(clen > 0 && len > 0) {
			len = read(src, buff, sizeof(buff));
			if (len > 0) {
				write(dst, buff, len);
				tot += len;
			}
			clen -= len;
		}
	} else {
		printf("Receiving data...\n");
		while(len > 0) {
			len = read(src, buff, sizeof(buff));
			if (len > 0) {
				write(dst, buff, len);
				tot += len;
			}
		}		
	}

	printf("Received %d bytes\n", tot);
	
	close(src);
	close(dst);

	chmod(path, 0755);
	free(path);
}
