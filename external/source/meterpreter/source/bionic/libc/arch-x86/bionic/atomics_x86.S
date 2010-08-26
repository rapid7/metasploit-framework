#include <sys/linux-syscalls.h>

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1


/*
 * int __futex_wait(volatile void *ftx, int val, const struct timespec *timeout)
 */
.text
.globl __futex_wait
.type __futex_wait, @function
.align 4
__futex_wait:
    pushl   %ebx
    pushl   %esi
    mov     12(%esp), %ebx           /* ftx */
    movl    $FUTEX_WAIT, %ecx
    mov     16(%esp), %edx           /* val */
    mov     20(%esp), %esi           /* timeout */
    movl    $__NR_futex, %eax
    int     $0x80
    popl    %esi
    popl    %ebx
    ret


/* int __futex_wake(volatile void *ftx, int count) */

.text
.globl __futex_wake
.type __futex_wake, @function
.align 4
__futex_wake:
    pushl   %ebx
    mov     8(%esp), %ebx            /* ftx */
    movl    $FUTEX_WAKE, %ecx
    mov     12(%esp), %edx           /* count */
    movl    $__NR_futex, %eax
    int     $0x80
    popl    %ebx
    ret

/* int __futex_syscall3(volatile void *ftx, int op, int count) */
.text
.globl __futex_syscall3
.type __futex_syscall3, @function
.align 4
__futex_syscall3:
    pushl   %ebx
    movl    8(%esp), %ebx      /* ftx */
    movl    12(%esp), %ecx      /* op */
    movl    16(%esp), %edx      /* value */
    movl    $__NR_futex, %eax
    int     $0x80
    popl    %ebx
    ret

/* int __futex_syscall4(volatile void *ftx, int op, int val, const struct timespec *timeout) */
.text
.globl __futex_syscall4
.type __futex_syscall4, @function
.align 4
__futex_syscall4:
    pushl   %ebx
    pushl   %esi
    movl    12(%esp), %ebx      /* ftx */
    movl    16(%esp), %ecx      /* op */
    movl    20(%esp), %edx      /* val */
    movl    24(%esp), %esi      /* timeout */
    movl    $__NR_futex, %eax
    int     $0x80
    popl    %esi
    popl    %ebx
    ret

/* int __atomic_cmpxchg(int old, int new, volatile int* addr) */

.text
.globl __atomic_cmpxchg
.type __atomic_cmpxchg, @function
.align 4
__atomic_cmpxchg:
    mov     4(%esp), %eax             /* old */
    mov     8(%esp), %ecx             /* new */
    mov     12(%esp), %edx            /* addr */
    lock cmpxchg %ecx, (%edx)
    jnz 1f
    xor    %eax, %eax
    jmp 2f
1:
    movl   $1, %eax
2:
    ret                               /* 0 == success, 1 == failure */


/* int __atomic_swap(int new, volatile int* addr) */

.text
.globl __atomic_swap
.type __atomic_swap, @function
.align 4
__atomic_swap:
    mov     4(%esp), %ecx             /* new */
    mov     8(%esp), %edx             /* addr */
    lock xchg %ecx, (%edx)
    mov     %ecx, %eax
    ret


/*
 * int __atomic_dec(volatile int* addr)
 *
 * My x86 asm is really rusty.. this is probably suboptimal
 */

.text
.globl __atomic_dec
.type __atomic_dec, @function
.align 4
__atomic_dec:
   pushl    %ebx
   pushl    %esi
   movl     12(%esp), %ebx             /* addr */

1:
   movl     (%ebx), %esi               /* old = *addr */
   movl     %esi, %edx
   subl     $1, %edx                   /* new = old - 1 */

   pushl    %ebx
   pushl    %edx
   pushl    %esi
   call     __atomic_cmpxchg
   addl     $12, %esp
   test     %eax, %eax
   jnz      1b

   movl     %esi, %eax               /* return old */
   popl     %esi
   popl     %ebx
   ret


.text
/* int __atomic_inc(volatile int* addr) */
.globl __atomic_inc
.type __atomic_inc, @function
.align 4
__atomic_inc:
   pushl    %ebx
   pushl    %esi
   movl     12(%esp), %ebx             /* addr */

1:
   movl     (%ebx), %esi               /* old = *addr */
   movl     %esi, %edx
   addl     $1, %edx                   /* new = old + 1 */

   pushl    %ebx
   pushl    %edx
   pushl    %esi
   call     __atomic_cmpxchg
   addl     $12, %esp
   test     %eax, %eax
   jnz      1b

   movl     %esi, %eax               /* return old */
   popl     %esi
   popl     %ebx
   ret

