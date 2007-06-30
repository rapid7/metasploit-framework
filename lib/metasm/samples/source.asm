sys_write equ 4
sys_exit  equ 1
stdout    equ 1

syscall macro nr
 mov eax, nr // the syscall number goes in eax
 int 80h
endm

 nop nop
 call foobar
toto_str db "toto\n"
toto_str_len equ $ - toto_str

foobar:
; setup write arguments
 mov ebx, stdout		; fd
 call got_eip
got_eip: pop ecx
 add ecx, toto_str - got_eip	// buf
 mov edx, toto_str_len		; buf_len
 syscall(sys_write)

 /*
 ; hang forever
 jmp $
 */

 xor ebx, ebx
 syscall(sys_exit)
