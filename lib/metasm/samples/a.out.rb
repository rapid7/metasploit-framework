#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

#
# here we build a simple a.out executable
#

require 'metasm'

Metasm::AOut.assemble(Metasm::Ia32.new, <<EOS).encode_file('m-a.out')
.text
.entrypoint
mov eax, 4
mov ebx, 1

.data
str db "kikoo\\n"
strend:

.text
mov ecx, str
mov edx, strend - str
int 80h		// linux sys_write

mov eax, 1
mov ebx, 42
int 80h		// linux sys_exit
ret
EOS
