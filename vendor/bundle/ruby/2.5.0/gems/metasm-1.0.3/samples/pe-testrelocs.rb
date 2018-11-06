#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


#
# in this sample we compile 2 PE files, one executable and one dll
# with the same base address, to check if the base relocation table
# of the dll is correctly encoded
#

require 'metasm'

cpu = Metasm::Ia32.new

pe = Metasm::PE.assemble cpu, <<EOS
.image_base 0x50000
.section '.text' r w x	; allows merging iat/data/etc
.entrypoint
call foobarplt
xor eax, eax
ret

.import 'pe-foolib' foobar foobarplt
EOS
pe.encode_file('pe-testreloc.exe', 'exe')

dll = Metasm::PE.assemble cpu, <<EOS
.image_base 0x50000
.section '.text' r w x
foobar:
push 0
push msg	; use non-position independant code
push title
push 0
call msgbox

xor eax, eax
ret

.align 4
msg db 'foo', 0
title db 'bar', 0

.import user32 MessageBoxA msgbox
.export foobar
.libname 'pe-foolib'
EOS
dll.encode_file('pe-foolib.dll', 'dll')
