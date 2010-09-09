#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'test/unit'
require 'metasm'

class TestMips < Test::Unit::TestCase

	def test_enc
		sc = Metasm::Shellcode.assemble(Metasm::MIPS.new(:big), <<EOS)
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

	li	$14, -5			; 4 passes
	nor	$14, $14, $0		; put number of passes in $14

	li	$11,-73			; addend to calculated PC is 73
;.set noreorder
next:
	bltzal  $8, next
;.set reorder
	slti	$8, $0, 0x8282
	nor	$11, $11, $0		; addend in $9
	addu	$25, $31, $11		; $25 points to encoded shellcode +4
;	addu	$16, $31, $11		; $16 too (enable if you want to pass correct parameters to cacheflush

;	lui	$2, 0xDDDD		; first part of the xor (old method)
	slti	$23, $0, 0x8282 	; store 0 in $23 (our counter)
;	ori	$17, $2, 0xDDDD 	; second part of the xor (old method)
	lw	$17, -4($25)		; load xor key in $17


	li	$13, -5
	nor	$13, $13, $0		; 4 in $13

	addi	$15, $13, -3		; 1 in $15
loop:
	lw	$8, -4($25)

	addu	$23, $23, $15		; increment counter
	xor	$3, $8, $17
	sltu	$30, $23, $14		; enough loops?
	sw	$3, -4($25)
	addi	$6, $13, -1		; 3 in $6 (for cacheflush)
	bne	$0, $30, loop
	addu	$25, $25, $13		; next instruction to decode :)


;	addiu	$4, $16, -4		; not checked by Linux
;	li	$5,40			; not checked by Linux
;	li	$6,3			; $6 is set above

;	.set	noreorder
	li	$2, 4147		; cacheflush
	;.ascii "\\x01JT\\x0c"		; nul-free syscall
	syscall 0x52950
;	.set	reorder


					; write last decoder opcode and decoded shellcode
;	li	$4,1			; stdout
;	addi	$5, $16, -8
;	li	$6,40			; how much to write
;	.set	noreorder
;	li	$2, 4004		; write
;	syscall
;	.set	reorder


	nop				; encoded shellcoded must be here (xor key right here ;)
; $t9 (aka $25) points here
EOS
		# ruby19 string.encoding. What a wonderful feature!
		# if we use a "\x<80 or more>", the encoding is 8bits
		# '' << "\x80" => 8bits
		# '' << 0x80 => ascii
		# Edata.data is ascii for now, so this is needed to make the test work.
		str = ''
		"\x24\x0e\xff\xfb\x01\xc0\x70\x27\x24\x0b\xff\xb7\x05\x10\xff\xff\x28\x08\x82\x82\x01\x60\x58\x27\x03\xeb\xc8\x21\x28\x17\x82\x82\x8f\x31\xff\xfc\x24\x0d\xff\xfb\x01\xa0\x68\x27\x21\xaf\xff\xfd\x8f\x28\xff\xfc\x02\xef\xb8\x21\x01\x11\x18\x26\x02\xee\xf0\x2b\xaf\x23\xff\xfc\x21\xa6\xff\xff\x17\xc0\xff\xf9\x03\x2d\xc8\x21\x24\x02\x10\x33\x01\x4a\x54\x0c\0\0\0\0".each_byte { |b| str << b }
		assert_equal(str, sc.encoded.data)

		dasm_src = Metasm::Shellcode.disassemble(Metasm::MIPS.new(:big), sc.encoded.data).to_s
		lines = dasm_src.respond_to?(:lines) ? dasm_src.lines : dasm_src.to_a
		assert_equal(28, lines.grep(/\S/).length)
	end
end
