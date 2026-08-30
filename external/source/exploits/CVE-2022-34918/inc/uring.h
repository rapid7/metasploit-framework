#ifndef _URING_H_
#define _URING_H_

#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/io_uring.h>

#define SPRAY_NB_ENTRIES 10

struct fd_uring {
    int fd;
    struct io_uring_params *params;
};

static inline int io_uring_setup(uint32_t entries, struct io_uring_params *p) {
    return syscall(__NR_io_uring_setup, entries, p);
}

static inline int io_uring_register(int fd, unsigned int opcode, void *arg, unsigned int nr_args) {
    return syscall(__NR_io_uring_register, fd, opcode, arg, nr_args);
}

void spray_uring(uint32_t spray_size, struct fd_uring *fd_buffer);
void release_uring(struct fd_uring *fd_buffer, uint32_t buffer_size);

#endif /* _URING_H_ */
