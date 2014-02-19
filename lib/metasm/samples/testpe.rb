#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


#
# a sample application
#


require 'metasm'

pe = Metasm::PE.assemble Metasm::Ia32.new, <<EOS
.entrypoint
push 0
push title
push message
push 0
call messagebox

xor eax, eax
ret

.import 'user32' MessageBoxA messagebox

.data
message db 'kikoo lol', 0
title   db 'blaaa', 0
EOS
pe.encode_file 'testpe.exe'
