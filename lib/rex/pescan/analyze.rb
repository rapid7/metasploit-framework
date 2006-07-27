module Rex
module PeScan
module Analyze

	class Fingerprint
		attr_accessor :pe
		
		def initialize(pe)
			self.pe = pe
		end
		
		def config(param)
			@sigs = {}
			
			name = nil
			regx = ''
			epon = 0
			sidx = 0
			
			fd = File.open(param['database'], 'r')
			fd.each_line do |line|
				case line
				when /^\s*#/
					next
				when /\[\s*(.*)\s*\]/
					if (name)
						@sigs[ name ] = [regx, epon]
					end
					name = $1 + " [#{ sidx+=1 }]"
					epon = 0
					next
				when /signature\s*=\s*(.*)/
					pat = $1.strip
					regx = ''
					pat.split(/\s+/).each do |c|
						next if c.length != 2
						regx << (c.index('?') ? '.' : "\\x#{c}")
					end
				when /ep_only\s*=\s*(.*)/
					epon = ($1 =~ /^T/i) ? 1 : 0
				end
			end
			
			if (name and ! @sigs[name])
				@sigs[ name ] = [regx, epon]
			end
			
			fd.close
		end
		
		def scan(param)
			config(param)

			epa = pe.hdr.opt.AddressOfEntryPoint
			buf = pe.read_rva(epa, 256)
			
			@sigs.each_pair do |name, data|
				begin
				if (buf.match(Regexp.new('^' + data[0])))
					$stdout.puts param['file'] + ": " + name
				end
				rescue RegexpError
					$stderr.puts "Invalid signature: #{name} #{data[0]}"
				end
			end
		end	
	end
	
end
end
end
