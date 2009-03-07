.pt_gnu_stack rw	// elf-specific instruction
//.interp none		// request minimal elf, no section/dynamic/interpreter

#define __i386__
#include <asm/unistd.h>	// can use the C preprocessor

stdout    equ 1		// 'equ' constant definition

syscall macro nr	// asm-style macros
 mov eax, nr		; the syscall number goes in eax
 int 80h
endm

#define syscall1(nr, arg) mov ebx, arg  syscall(__NR_##nr)	// c++-style macros
#define syscall3(nr, arg1, arg2, arg3) mov edx, arg3  mov ecx, arg2  syscall1(nr, arg1)

.entrypoint		// the elf entrypoint
 nop nop
 call 1f		// 1f is the first label named '1' found forward
toto_str db "toto\n"
toto_str_len equ $ - toto_str	// $ is the address of the start of the current instruction/data

1:
 pop ebp

syscall3(write, stdout, ebp, toto_str_len)

/*
; hang forever
 jmp $
*/

syscall1(exit, 0)
hlt
