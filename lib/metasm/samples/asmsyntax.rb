#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm'
require 'metasm-shell'

# padding
edata = <<EOS.encode_edata
inc ebx
jmp toto

pre_pad:
.pad 90h	; this statement will be replaced by the right number of 0x90 to honor the next .offset directive
post_pad:

toto:
.offset 24 + ((3-12) >> 8)	; we are now at 24 bytes from the beginning of the shellcode (inc ebx)
				; .offset accepts an arbitrary expression, but unresolved variables are not allowed
mov eax, [ebx + ((kikoo<<1) - 4*lol)]	; all immediate value can be an arbitrary arithmetic/logic expression

.padto 38, db 3 dup(0b0110_0110)	; fill space till byte 30 with the specified data structure (same as .pad + .offset)

inc eax

.align 16, dw foobar + 42

ret

#ifdef BLABLA
you can also use any preprocessor directive (gcc-like syntax)
# elif defined(HOHOHO) && 42
 # error 'infamous error message'
#else
#define test(ic)	((ic) - \
			 4)
#endif
EOS

edata.fixup 'foobar' => 1	# fixup the value of 'foobar'
newdata = 'somestring'
edata.patch 'pre_pad', 'post_pad', newdata		# replace the (beginning of the) segment beetween the labels by a string
#edata.patch 'pre_pad', 'post_pad', 'waaaaaaaaaay tooooooooooooooooooooooooooooooooooooooooo big !!!!'	# raise an error

edata.fixup 'kikoo' => 8, 'lol' => '42'	# fixup the immediate value

p edata.data # show the resulting raw string
