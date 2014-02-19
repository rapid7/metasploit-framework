#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


#
# quick demonstration that the disassembler's backtracker works
#

require 'metasm'
Metasm.require 'samples/metasm-shell'

puts <<EOS.encode.decode
.base_addr 0

; compute jump target
mov ebx, 0x12345678
mov eax, ((toto + 12) ^ 0x12345678)
xor eax, ebx
sub eax, 12

; jump
call eax

; trap
add eax, 42
; die, you vile reverser !
db 0e9h

; real target
toto:
mov eax, 28h
pop ebx
ret

EOS
