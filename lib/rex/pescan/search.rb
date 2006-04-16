module Rex
module PeScan
module Search

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
			
			# Adjust based on -A and -B flags
			pre = param['before'] || 0
			suf = param['after']  || 16
			
			@address -= pre
			@address = 0 if (@address < 0 || ! @address)
			buf = pe.read_rva(@address, suf)
			$stdout.puts "0x%08x %s" % [  pe.rva_to_vma(@address), buf.unpack("H*") ]
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
