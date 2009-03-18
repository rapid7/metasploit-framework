#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <pthread.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>

void usage(char* argv0)
{
    fprintf(stderr, "usage: %s [ -t ] [ -p <port> ]\n", argv0);
}

int read_and_exec(int s)
{
    int n, length;
    int (*payload)(void);

    fprintf(stderr, "Reading length... ");
    if ((n = recv(s, &length, sizeof(length), 0)) != sizeof(length)) {
        if (n < 0)
            perror("recv");
        else
            fprintf(stderr, "recv: short read\n");
        return -1;
    }
    fprintf(stderr, "%d\n", length);

    fprintf(stderr, "Allocating buffer... ");
    if ((payload = mmap(NULL, length, PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_ANON | MAP_PRIVATE, -1, 0)) == (void*)-1) {
        perror("mmap");
        return -1;
    }
    fprintf(stderr, "0x%x\n", payload);

    fprintf(stderr, "Reading payload... ");
    if ((n = recv(s, payload, length, 0)) != length) {
        if (n < 0)
            perror("recv");
        else
            fprintf(stderr, "recv: short read\n");
        return -1;
    }
    fprintf(stderr, "read %d bytes\n", n);

    fprintf(stderr, "Executing payload...\n");
    
    (void*)(*payload)();
    
    return 0;
}

void* read_and_exec_thread(void* arg)
{
    return (void*)read_and_exec((int)arg);
}

int create_read_and_exec_thread(int c)
{
    int err;
    pthread_t pthread;
    void* return_value;
    
    if ((err = pthread_create(&pthread, NULL,
                              read_and_exec_thread, (void*)c)) != 0) {
        fprintf(stderr, "pthread_create: %s\n", strerror(err));
        return -1;
    }

    if ((err = pthread_join(pthread, &return_value)) != 0) {
        fprintf(stderr, "pthread_join: %s\n", strerror(err));
        return -1;
    }
}

int main(int argc, char* argv[])
{
    int c, s, val, threaded = 0;
    socklen_t salen;
    struct sockaddr_in saddr, client_saddr;
    short port = 1234;
    
    while ((c = getopt(argc, argv, "tp:")) != EOF) {
        switch (c) {
        case 'p':
            port = atoi(optarg);
            break;
        case 't':
            threaded = 1;
            break;
        default:
            usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if ((s = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    val = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    bzero(&saddr, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(port);
    saddr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(s, (struct sockaddr*)&saddr, sizeof(saddr)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    if (listen(s, 5) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    if ((c = accept(s, (struct sockaddr*)&client_saddr, &salen)) < 0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    if (threaded)
        exit(create_read_and_exec_thread(c));
    else
        exit(read_and_exec(c));
}
