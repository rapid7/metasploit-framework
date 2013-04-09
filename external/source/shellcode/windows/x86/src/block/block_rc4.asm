;-----------------------------------------------------------------------------;
; Author: Michael Schierl (schierlm[at]gmx[dot]de)
; Version: 1.0 (29 December 2012)
;-----------------------------------------------------------------------------;
[BITS 32]

; Input: EBP - Data to decode
;        ECX - Data length
;        ESI - Key (16 bytes for simplicity)
;        EDI - pointer to 0x100 bytes scratch space for S-box
; Direction flag has to be cleared
; Output: None. Data is decoded in place.
; Clobbers: EAX, EBX, ECX, EDX, EBP (stack is not used)

  ; Initialize S-box
  xor eax, eax           ; Start with 0
init:
  stosb                  ; Store next S-Box byte S[i] = i
  inc al                 ; increase byte to write (EDI is increased automatically)
  jnz init               ; loop until we wrap around
  sub edi, 0x100         ; restore EDI

  ; permute S-box according to key
  xor ebx, ebx           ; Clear EBX (EAX is already cleared)
permute:
  add bl, [edi+eax]      ; BL += S[AL] + KEY[AL % 16]
  mov edx, eax
  and dl, 0xF
  add bl, [esi+edx]
  mov dl, [edi+eax]      ; swap S[AL] and S[BL]
  xchg dl, [edi+ebx]
  mov [edi+eax], dl
  inc al                 ; AL += 1 until we wrap around
  jnz permute


  ; decryption loop
  xor ebx, ebx           ; Clear EBX (EAX is already cleared)
decrypt:
  inc al                 ; AL += 1
  add bl, [edi+eax]      ; BL += S[AL]
  mov dl, [edi+eax]      ; swap S[AL] and S[BL]
  xchg dl, [edi+ebx]
  mov [edi+eax], dl
  add dl, [edi+ebx]      ; DL = S[AL]+S[BL]
  mov dl, [edi+edx]      ; DL = S[DL]
  xor [ebp], dl          ; [EBP] ^= DL
  inc ebp                ; advance data pointer
  dec ecx                ; reduce counter
  jnz decrypt            ; until finished
