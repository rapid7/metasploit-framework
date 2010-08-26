.text
.align 4
.type __bionic_call_ctors, @function

/*
 * The CTORS_LIST is marked by -1 (start) and 0 (end).
 * We mark the end of the .ctors section with the __CTOR_END__ section so
 * that we can just iterate backwards from it until we hit -1 and execute
 * all the function pointers. This seems to be the way to do it for SVR4
 * derived systems.
 */
__bionic_call_ctors:
    pushl  %esi
    mov    $__CTOR_END__, %esi

0:
    /* now grab the next function pointer and check if its -1. If not,
     * call it, otherwise we're done. We use %esi since it's callee saved.
     */
    subl    $4, %esi
    mov     (%esi), %eax
    cmp     $0xffffffff, %eax
    je      1f
    call    *%eax
    jmp     0b

1:
    /* we're done */
    popl    %esi
    ret

.section .init
.align 4
    call __bionic_call_ctors
    ret

.section .ctors, "aw", @progbits
.align 4
.type __CTOR_END__, @object
__CTOR_END__:
    .long 0

.section .init_array, "aw"
    .long 0

.section .fini_array, "aw"
    .long 0
