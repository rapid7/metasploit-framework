#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# 
# in this exemple we decode a PE file, and disassemble its instructions from
# its entrypoint. We then dump the whole thing to standard out.
#

require 'metasm'

raise 'usage: script <pe filename>' if not filename = ARGV.shift

# load and decode the file
pe = Metasm::PE.decode_file filename, Metasm::Ia32.new

# disassemble instructions
pe.disassemble pe.optheader.entrypoint + pe.optheader.image_base

# dump
puts pe.blocks_to_src
