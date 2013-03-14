# -*- coding: binary -*-
module Rex
module PeScan
module Search

	require "rex/assembly/nasm"

	class DumpRVA
		attr_accessor :pe

		def initialize(pe)
			self.pe = pe
		end

		def config(param)
			@address = pe.vma_to_rva(param['args'])
		end

		def scan(param)
			config(param)

			$stdout.puts "[#{param['file']}]"

			# Adjust based on -A and -B flags
			pre = param['before'] || 0
			suf = param['after']  || 16

			@address -= pre
			@address = 0 if (@address < 0 || ! @address)

			begin
				buf = pe.read_rva(@address, suf)
			rescue ::Rex::PeParsey::WtfError
				return
			end

			$stdout.puts pe.ptr_s(pe.rva_to_vma(@address)) + " " + buf.unpack("H*")[0]
			if(param['disasm'])
				insns = []
				buf.gsub!("; ", "\n")
				if buf.include?("retn")
					buf.gsub!("retn", "ret")
				end
				d2 = Metasm::Shellcode.disassemble(Metasm::Ia32.new, buf)
				addr = 0
				while ((di = d2.disassemble_instruction(addr)))
					insns << di.instruction
					disasm = "0x%08x\t" % (pe.rva_to_vma(@address) + addr)
					disasm << di.instruction.to_s
					$stdout.puts disasm
					addr = di.next_addr
				end
			end

		end
	end

	class DumpOffset < DumpRVA
		def config(param)
			begin
				@address = pe.file_offset_to_rva(param['args'])
			rescue Rex::PeParsey::BoundsError
			end
		end
	end
end
end
end
