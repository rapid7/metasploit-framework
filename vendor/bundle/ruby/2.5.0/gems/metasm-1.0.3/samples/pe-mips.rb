#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

#
# here we assemble a dummy MIPS PE
# TODO autodetect header.machine from cpu, find something to put in
# the MZ header, make a real mips sample program
#


require 'metasm'

cpu = Metasm::MIPS.new(:little)
prog = Metasm::PE.assemble(cpu, <<EOS)
.text
.entrypoint
lui r4, 0x42
jal toto
add r4, r1, r2
jr r31
nop

toto:
jr r31
;ldc1 fp12, 28(r4)
nop

.import 'foobar' 'baz'
EOS
prog.header.machine='R4000'
data = prog.encode_file 'mipspe.exe'

