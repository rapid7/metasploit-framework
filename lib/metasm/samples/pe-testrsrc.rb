#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


#
# compiles a PE file with the specified resource directory
# TODO build an icon or something
#

require 'metasm'

pe = Metasm::PE.assemble Metasm::Ia32.new, <<EOS
.entrypoint
  xor eax, eax
  ret
EOS

rsrc = { 1 => { 1 => { 2 => 'xxx' }, 'toto' => { 12 => 'tata' } } }
pe.resource = Metasm::COFF::ResourceDirectory.from_hash rsrc

pe.encode_file('pe-testrsrc.exe')
