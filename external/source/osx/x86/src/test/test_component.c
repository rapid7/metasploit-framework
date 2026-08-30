/*
 * test_component: Read in a component and execute it
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>

int read_and_exec_file(char* file)
{
    char* buf = malloc(10000);
    int f, n;

    if ((f = open(file, O_RDONLY, 0)) < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    
    if ((n = read(f, buf, 100000)) < 0) {
        perror("read");
        exit(EXIT_FAILURE);
    }

    //printf("==> Read %d bytes, executing component...\n", n);
    
    ((void(*)(void))buf)();

    printf("==> Done.\n");

    return 0;
}

int create_read_and_exec_thread(char* file)
{
    int err;
    pthread_t pthread;
    void* return_value;
    
    if ((err = pthread_create(&pthread, NULL,
                              read_and_exec_file, (void*)file)) != 0) {
        fprintf(stderr, "pthread_create: %s\n", strerror(err));
        return -1;
    }

    if ((err = pthread_join(pthread, &return_value)) != 0) {
        fprintf(stderr, "pthread_join: %s\n", strerror(err));
        return -1;
    }

    return 0;
}

int main(int argc, char* argv[])
{
    int c;
    int threaded = 0;
    
    while ((c = getopt(argc, argv, "tp:")) != EOF) {
        switch (c) {
        case 't':
            threaded = 1;
            break;
        default:
            fprintf(stderr, "usage: %s [ -t ] payload_bin\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }


    if (threaded)
        create_read_and_exec_thread(argv[optind]);
    else
        read_and_exec_file(argv[optind]);
}
