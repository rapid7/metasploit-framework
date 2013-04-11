;-----------------------------------------------------------------------------;
; Author: Michael Schierl (schierlm[at]gmx[dot]de)
; Version: 1.0 (29 December 2012)
;-----------------------------------------------------------------------------;

;
; c1 = OpenSSL::Cipher::Cipher.new('RC4')
; c1.encrypt
; c1.key="Hello, my world!"
; c1.update("This is some magic data you may want to have encoded and decoded again").unpack("H*")
;
; => "882353c5de0f5e6b10bf0d25c432c5d16424dc797e895f37f261c893b31d577e7e69f77e07aa576d58c7f757164e7d74988feb10f972b28dcfa1e3a2b1cc0b0fa1a8b116294b"
;
; c1 = OpenSSL::Cipher::Cipher.new('RC4')
; c1.decrypt
; c1.key="Hello, my world!"
; c1.update(["882353c5de0f5e6b10bf0d25c432c5d16424dc797e895f37f261c893b31d577e7e69f77e07aa576d58c7f757164e7d74988feb10f972b28dcfa1e3a2b1cc0b0fa1a8b116294b"].pack("H*"))
;
; => "This is some magic data you may want to have encoded and decoded again"
;

[BITS 32]
[ORG 0]

  cld                    ; Clear the direction flag.
  call pushkey           ; push the address of the key onto the stack
  db "Hello, my world!"
pushkey:
  pop esi                ; and store it into ESI
  call pushdata          ; push the address of the encrypted data on the stack
  db 0x88, 0x23, 0x53, 0xc5, 0xde, 0x0f, 0x5e, 0x6b, 0x10, 0xbf, 0x0d, 0x25, 0xc4, 0x32, 0xc5, 0xd1, 0x64, 0x24, 0xdc, 0x79, 0x7e, 0x89, 0x5f, 0x37, 0xf2, 0x61, 0xc8, 0x93, 0xb3, 0x1d, 0x57, 0x7e, 0x7e, 0x69, 0xf7, 0x7e, 0x07, 0xaa, 0x57, 0x6d, 0x58, 0xc7, 0xf7, 0x57, 0x16, 0x4e, 0x7d, 0x74, 0x98, 0x8f, 0xeb, 0x10, 0xf9, 0x72, 0xb2, 0x8d, 0xcf, 0xa1, 0xe3, 0xa2, 0xb1, 0xcc, 0x0b, 0x0f, 0xa1, 0xa8, 0xb1, 0x16, 0x29, 0x4b
pushdata:
  pop ebp                ; and store it into EBP
  mov ecx, 70            ; store data length into ECX
  sub esp, 0x100         ; make space on stack for S-Box
  mov edi, esp           ; and store address into EDI
  nop
  nop
  nop
  int 3                  ; for stepping through the code
                         ; let's run the RC4 decoder
%include "./src/block/block_rc4.asm"
  int 3                  ; EBP should point to decoded data now
