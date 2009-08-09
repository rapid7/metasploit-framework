#include "SYS.h"

.globl HIDENAME(cerror)
	
        /*
         * The __error() function is thread aware. For non-threaded
         * programs and the initial threaded in threaded programs,
         * it returns a pointer to the global errno variable.
         */
        .globl  CNAME(__error)
        .type   CNAME(__error),@function
HIDENAME(cerror):	
        pushq   %rax
        call    PIC_PLT(CNAME(__error))
        popq    %rcx
        movl    %ecx,(%rax)
        movq    $-1,%rax
        movq    $-1,%rdx
        ret

