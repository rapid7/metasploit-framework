#include <sys/linux-syscalls.h>

.text
.type _exit_with_stack_teardown, @function
.globl _exit_with_stack_teardown
.align 4

/*
 * void _exit_with_stack_teardown(void *stackBase, int stackSize, int *retCode) 
 */

_exit_with_stack_teardown:
    /* we can trash %ebx here since this call should never return. */
    /* We can also take advantage of the fact that the linux syscall trap
     * handler saves all the registers, so we don't need a stack to keep
     * the retCode argument for exit while doing the munmap */

    /* TODO(dmtriyz): No one expects this code to return, so even if
     * munmap fails, we have to exit. This should probably be fixed, but
     * since ARM side does the same thing, leave it as is.
     */
    mov     4(%esp), %ebx             /* stackBase */
    mov     8(%esp), %ecx             /* stackSize */
    mov     12(%esp), %edx           /* retCode, not used for munmap */
    mov     $__NR_munmap, %eax
    int     $0x80
    mov     %edx, %ebx                /* retrieve the retCode */
    movl    $__NR_exit, %eax
    int     $0x80
    /* exit does not return */
    /* can't have a ret here since we no longer have a usable stack. Seems
     * that presently, 'hlt' will cause the program to segfault.. but this
     * should never happen :) */
    hlt
