#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# 
# this script disassembles an executable (elf/pe) and dumps the output
# ruby [-v|-d] disassemble.rb [options] <exe file> [<c header file>] [<entrypoints>]
# options:
#   --no-data		do not display data sections
#   --no-data-trace	do not backtrace for data access (r/w xrefs)
#

require 'metasm'
include Metasm

# parse arguments
no_data = ARGV.delete('--no-data')
no_data_trace = ARGV.delete('--no-data-trace')
exename = ARGV.shift
cheader = ARGV.shift

# load the file
exe = AutoExe.decode_file exename
# set options
d = exe.init_disassembler
d.parse_c_file cheader if cheader
d.backtrace_maxblocks_data = -1 if no_data_trace
# do the work
begin
	if ARGV.empty?
		exe.disassemble
	else
		ARGV.each { |ep|
			ep = Integer(ep) if ep =~ /^0x[0-9a-f]+$/
			exe.disassemble ep
		}
	end
rescue Interrupt
	puts $!, $!.backtrace
end
# output
d.dump(!no_data)
