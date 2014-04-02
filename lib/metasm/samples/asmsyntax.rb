#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# this script show the assembler syntax understood by the framework

require 'metasm'

edata = Metasm::Shellcode.assemble(Metasm::Ia32.new, <<EOS).encoded
#line 12	// preprocessor directive (useful in case of syntax error)

// data specification
db 42h		; a single byte
db 'a'		; same thing
dd 0x48, 0x7, 4 dup(0x19)	; 6 double words
dd toto + 4*pre_pad	; data may refer to labels in arbitrary expressions
db "foo", 0	; null-terminated string
dw "foo", 0	; null-terminated wide string
dd 0b010111101100	; binary constant
dd someexternalvar+12	; an external variable to be fixed up later

// code
inc ebx
jmp toto
mov eax, [fs:ebx + ((kikoo<<1) - 4*lol)]	; all immediate values can be an arbitrary arithmetic/logic expression
push.i16 0x1234		; specific opcode forms are defined using this kind of syntax

// labels
pre_pad:
// parser instructions
.pad 90h	; this statement will be replaced by the right number of 0x90 to honor the next .offset directive
post_pad:

toto:
.offset 74 + (12-48>>4)*0	; we are now at 74 bytes from the beginning of the shellcode (db 42h)
				; .offset accepts an arbitrary expression

.padto toto+38, db 3 dup(0b0110_0110)	; fill space with the specified data structure until 38 bytes after toto (same as .pad + .offset)

inc eax

.align 16, dw foobar + 42

local1:
1:	// a local label (any integer allowed)
jmp 1b	// 1b => last '1' label (same as local1)
jmp 1f	// 1f => next '1' label (same as local2)

local2:
1:	// local labels can be redefined as often as needed
mov eax, 1b	// same as local2

ret

#ifdef BLABLA
 you can also use any preprocessor directive (gcc-like syntax)
 #pragma include_dir "/some/directory"
 #include <foobar>
# elif defined(HOHOHO) && 42
 #error 'infamous error message'
#else
 #define test(ic)	((ic) - \
			 4)
#endif

EOS

edata.fixup 'foobar' => 1	# fixup the value of 'foobar'
newdata = 'somestring'
edata.patch 'pre_pad', 'post_pad', newdata		# replace the (beginning of the) segment beetween the labels by a string
#edata.patch 'pre_pad', 'post_pad', 'waaaaaaaaaay tooooooooooooooooooooooooooooooooooooooooo big !!!!'	# raise an error

edata.fixup 'kikoo' => 8, 'lol' => 42	# fixup the immediate values
edata.fixup 'someexternalvar' => 0x30303030	# fixup the external used in the data segment

p edata.data # show the resulting raw string
