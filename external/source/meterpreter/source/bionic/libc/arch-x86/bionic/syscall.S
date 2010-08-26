/*
 * Generic syscall call.
 * Upon entry
 *	%eax: system call number
 *	%ebx: arg0 to system call
 *	%ecx: arg..
 *	%edx: arg..
 *	%esi: arg..
 *	%edi: arg..
 * We push these (to save them) load them up with the
 * values from the calling frame (not all will actually be valid)
 * and make the syscall.
 */

#include <sys/linux-syscalls.h>

    .text
    .type syscall, @function
    .globl syscall
    .align 4

syscall:
    push    %eax
    push    %ebx
    push    %ecx
    push    %edx
    push    %esi
    push    %edi
    mov     28(%esp),%eax
    mov     32(%esp),%ebx
    mov     36(%esp),%ecx
    mov     40(%esp),%edx
    mov     44(%esp),%esi
    mov     48(%esp),%edi

    int     $0x80

    cmpl    $-129, %eax
    jb      1f
    negl    %eax
    pushl   %eax
    call    __set_errno
    addl    $4, %esp
    orl     $-1, %eax
1:
    pop    %edi
    pop    %esi
    pop    %edx
    pop    %ecx
    pop    %ebx
    pop    %eax
    ret
