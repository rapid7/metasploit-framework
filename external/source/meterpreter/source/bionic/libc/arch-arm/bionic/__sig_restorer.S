.global __sig_restorer

/* This is the opcode sequence GDB looks for in order to recognize
   this stack frame as a signal trampoline (see sigaction.c) */
__sig_restorer:
    mov r7, #119 /* __NR_sigreturn */
    swi #0
