# This function is to be called when the shared library
# is unloaded through dlclose()
_on_dlclose:
    lea __dso_handle, %eax
    call __cxa_finalize
    ret

/* we put the _init() function here in case the user files for the shared
 * libs want to drop things into .init section.
 * We then will call our ctors from crtend_so.o */
.section .init
.align 4
.type _init, @function
.globl _init
_init:

.section .init_array, "aw"
.align 4
.type __INIT_ARRAY__, @object
.globl __INIT_ARRAY__
__INIT_ARRAY__:
    .long -1

.section .fini_array, "aw"
.align 4
.type __FINI_ARRAY__, @object
.globl __FINI_ARRAY__
__FINI_ARRAY__:
    .long -1
    .long _on_dlclose

.section .ctors, "aw"
.align 4
.type __CTOR_LIST__, @object
.globl __CTOR_LIST__
__CTOR_LIST__:
        .long -1

#include "__dso_handle.S"
