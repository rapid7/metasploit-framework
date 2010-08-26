#include <sys/linux-syscalls.h>

.text

/*
 * int  __pthread_clone(int (*fn)(void*), void *tls, int flags,
 *                      void *arg);
 */
.globl __pthread_clone
.type __pthread_clone, @function
.align 4
__pthread_clone:
        pushl   %ebx
        pushl   %ecx
        movl    16(%esp), %ecx
        movl    20(%esp), %ebx

        # insert arguments onto the child stack
        movl    12(%esp), %eax
        movl    %eax, -12(%ecx)
        movl    24(%esp), %eax
        movl    %eax, -8(%ecx)
        lea     (%ecx), %eax
        movl    %eax, -4(%ecx)

        movl    $__NR_clone, %eax
        int     $0x80
        test    %eax, %eax
        jns     1f

        # an error occured, set errno and return -1
        negl    %eax
        call    __set_errno
        orl     $-1, %eax
        jmp     2f

1:
        jnz     2f

        # we're in the child thread now, call __thread_entry
        # with the appropriate arguments on the child stack
        # we already placed most of them
        subl    $16, %esp
        jmp     __thread_entry
        hlt

2:
        popl    %ecx
        popl    %ebx
        ret

/* XXX: TODO: Add __bionic_clone here
 *            See bionic/bionic_clone.c and arch-arm/bionic/clone.S
 *            for more details...
 */
