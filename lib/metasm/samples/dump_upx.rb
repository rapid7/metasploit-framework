#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#    Original script and idea by Alexandre GAZET
#
#    Licence is LGPL, see LICENCE in the top-level directory


# 
# this script will load an upx-packed windows executable, find its
# original entrypoint by disassembling the UPX stub, set breakpoint on it,
# run the program, and dump the loaded image to an executable PE.
#
# usage: dump_upx.rb <packed.exe> [<dumped.exe>]
#

require 'metasm'
include Metasm

# TerminateProcess prototype: 2 arguments (int, int) ; return value = int
WinAPI.new_api 'kernel32', 'TerminateProcess', 'II I'

class UPXUnpacker < WinDbg
	# loads the file
	# find the oep by disassembling
	# run it until the oep
	# dump the memory image
	def initialize(file, dumpfile)
		@dumpfile = dumpfile || 'upx-dumped.exe'

		pe = PE.decode_file(file)
		puts 'disassembling UPX loader...'
		@oep = find_oep(pe)
		puts "oep found at #{@oep.to_s 16}"
		@baseaddr = pe.optheader.image_base
		super(file.dup)
		puts 'running...'
		debugloop
	end

	# disassemble the upx stub to find a cross-section jump (to the real entrypoint)
	def find_oep(pe)		
		dasm = pe.init_disassembler
		dasm.backtrace_maxblocks_data = -1	# speed up dasm
		dasm.disassemble 'entrypoint'
		
		jmp = dasm.decoded.find { |addr, di|
			di.instruction.opname == 'jmp' and
			s = dasm.get_section_at(di.instruction.args[0]) and
			s != dasm.get_section_at(addr)
		}[1].instruction

		dasm.normalize(jmp.args[0])
	end	

	# when the initial thread is created, set a hardware breakpoint to the entrypoint
	def handler_newthread(pid, tid, info)
		 super
		 puts "oep breakpoint set..."
		 ctx = get_context(pid, tid)
		 ctx[:dr0] = @oep
		 ctx[:dr6] = 0
		 ctx[:dr7] = 1
		 WinAPI::DBG_CONTINUE
	end
	
	# when our breakpoint hits, dump the file and terminate the process
	def handler_exception(pid, tid, info)
		if info.code == WinAPI::STATUS_SINGLE_STEP and
				get_context(pid, tid)[:eip] == @oep
			puts 'oep breakpoint hit !'
			puts 'dumping...'
			# dump the loaded pe to a genuine PE object
			dump = LoadedPE.memdump @mem[pid], @baseaddr, @oep
			# the UPX loader unpacks everything in the first section which is marked read-only in the PE header, we must make it writeable
			dump.sections.first.characteristics = %w[MEM_READ MEM_WRITE MEM_EXECUTE]
			# write the PE file
			dump.encode_file @dumpfile
			# kill the process
			WinAPI.terminateprocess(@hprocess[pid], 0)
			puts 'done.'
			WinAPI::DBG_CONTINUE
		else
			super
		end
	end	
end

if __FILE__ == $0
	UPXUnpacker.new(ARGV.shift, ARGV.shift)
end
