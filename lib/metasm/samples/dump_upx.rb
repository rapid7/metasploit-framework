#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#    Original script and idea by Alexandre GAZET
#
#    Licence is LGPL, see LICENCE in the top-level directory


# 
# this script will load an upx-packed windows executable, find its
# original entrypoint by disassembling the UPX stub, set breakpoint on it,
# run the program, and dump the loaded image to an executable PE.
#
# usage: dump_upx.rb <packed.exe> [<dumped.exe>] [<rva iat>]
#

require 'metasm'
include Metasm

class UPXUnpacker
	# loads the file
	# find the oep by disassembling
	# run it until the oep
	# dump the memory image
	def initialize(file, dumpfile, iat_rva=nil)
		@dumpfile = dumpfile || 'upx-dumped.exe'
		@iat = iat_rva

		puts 'disassembling UPX loader...'
		pe = PE.decode_file(file)
		@oep = find_oep(pe)
		raise 'cant find oep...' if not @oep
		puts "oep found at #{Expression[@oep]}"
		@baseaddr = pe.optheader.image_base
		@iat -= @baseaddr if @iat > @baseaddr	# va => rva

		@dbg = OS.current.create_process(file).debugger
		puts 'running...'
		debugloop
	end

	# disassemble the upx stub to find a cross-section jump (to the real entrypoint)
	def find_oep(pe)		
		dasm = pe.disassemble_fast 'entrypoint'
		
		return if not jmp = dasm.decoded.find { |addr, di|
			# check only once per basic block
			next if not di.block_head?
			b = di.block
			# our target has only one follower
			next if b.to_subfuncret.to_a.length != 0 or b.to_normal.to_a.length != 1
			to = b.to_normal.first
			# ignore jump to unmmaped address
			next if not s = dasm.get_section_at(to)
			# ignore jump to same section
			next if dasm.get_section_at(di.address) == s

			# gotcha !
			true
		}

		# now jmp is a couple [addr, di], we extract and normalize the oep from there
		dasm.normalize(jmp[1].block.to_normal.first)
	end	

	def debugloop
		# set up a oneshot breakpoint on oep
		@dbg.hwbp(@oep, :x, 1, true) { breakpoint_callback }
		@dbg.run_forever
		puts 'done'
	end

	def breakpoint_callback
		puts 'breakpoint hit !'

		# dump the process
		# create a genuine PE object from the memory image
		dump = LoadedPE.memdump @dbg.memory, @baseaddr, @oep, @iat

		# the UPX loader unpacks everything in sections marked read-only in the PE header, make them writeable
		dump.sections.each { |s| s.characteristics |= ['MEM_WRITE'] }

		# write the PE file to disk
		dump.encode_file @dumpfile

		puts 'dump complete'
	ensure
		# kill the process
		@dbg.kill
	end
end

if __FILE__ == $0
	# args: packed [unpacked] [iat rva]
	UPXUnpacker.new(ARGV.shift, ARGV.shift, (Integer(ARGV.shift) rescue nil))
end
