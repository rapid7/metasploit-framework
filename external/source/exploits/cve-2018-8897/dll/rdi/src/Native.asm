.code
	__swapgs PROC
		swapgs
		ret
	__swapgs ENDP

	__rollback_isr PROC
		mov rdx, [rsp]          ; rdx = Return pointer
		lea r8, [rsp+8h]        ; r8 = Old stack
		mov [rcx], rdx          ; isr stack.rip = Return pointer
		mov [rcx+18h], r8       ; isr stack.rsp = Old stack
		mov rsp, rcx            ; stack = isr stack
		iretq                   ; return
	__rollback_isr ENDP
		
	__set_gs_base PROC
		wrgsbase rcx
		ret
	__set_gs_base ENDP
		
	__readss PROC
		xor eax, eax
		mov ax, ss
		ret
	__readss ENDP

	__read_gs_base PROC
		rdgsbase rax
		ret
	__read_gs_base ENDP

	__triggervuln PROC
		mov [rcx+8*0], r12      ; save registers
		mov [rcx+8*1], r13
		mov [rcx+8*2], r14
		mov [rcx+8*3], r15
		mov [rcx+8*4], rdi
		mov [rcx+8*5], rsi
		mov [rcx+8*6], rbx
		mov [rcx+8*7], rbp
		mov [rcx+8*8], rsp
		pushfq
		pop [rcx+8*9]

		mov ss, word ptr [rdx]  ; Defer debug exception
		int 3                   ; Execute with interrupts disabled
		nop
		nop
		nop
		nop	

		mov r12, [rcx+8*0]      ; load registers
		mov r13, [rcx+8*1]
		mov r14, [rcx+8*2]
		mov r15, [rcx+8*3]
		mov rdi, [rcx+8*4]
		mov rsi, [rcx+8*5]
		mov rbx, [rcx+8*6]
		mov rbp, [rcx+8*7]
		mov rsp, [rcx+8*8]
		push [rcx+8*9]
		popfq
		ret
	__triggervuln ENDP


	__setxmm0 PROC
		movups xmm0, [rcx]
		ret
	__setxmm0 ENDP

	__setxmm1 PROC
		movups xmm1, [rcx]
		ret
	__setxmm1 ENDP

	__setxmm2 PROC
		movups xmm2, [rcx]
		ret
	__setxmm2 ENDP

	__setxmm3 PROC
		movups xmm3, [rcx]
		ret
	__setxmm3 ENDP

	__setxmm4 PROC
		movups xmm4, [rcx]
		ret
	__setxmm4 ENDP

	__setxmm5 PROC
		movups xmm5, [rcx]
		ret
	__setxmm5 ENDP

	__setxmm6 PROC
		movups xmm6, [rcx]
		ret
	__setxmm6 ENDP

	__setxmm7 PROC
		movups xmm7, [rcx]
		ret
	__setxmm7 ENDP

	__setxmm8 PROC
		movups xmm8, [rcx]
		ret
	__setxmm8 ENDP

	__setxmm9 PROC
		movups xmm9, [rcx]
		ret
	__setxmm9 ENDP

	__setxmm10 PROC
		movups xmm10, [rcx]
		ret
	__setxmm10 ENDP

	__setxmm11 PROC
		movups xmm11, [rcx]
		ret
	__setxmm11 ENDP

	__setxmm12 PROC
		movups xmm12, [rcx]
		ret
	__setxmm12 ENDP

	__setxmm13 PROC
		movups xmm13, [rcx]
		ret
	__setxmm13 ENDP

	__setxmm14 PROC
		movups xmm14, [rcx]
		ret
	__setxmm14 ENDP

	__setxmm15 PROC
		movups xmm15, [rcx]
		ret
	__setxmm15 ENDP	
end
