module Rex
module PeScan
module Analyze

	require "rex/ui/text/table"
	
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
			
			fd = File.open(param['database'], 'rb')
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
	
	class Information
		attr_accessor :pe
		
		def initialize(pe)
			self.pe = pe
		end

		def add_fields(tbl, obj, fields)
			fields.each do |name|
				begin
					tbl << [name, "0x%.8x" % obj.send(name)]
				rescue ::NoMethodError => e
					$stderr.puts "Invalid field #{name}"
				end
			end
		end

		def scan(param)
			
			$stdout.puts "\n\n"
			
			tbl = table("Image Headers", ['Name', 'Value'])
			add_fields(tbl, pe.hdr.file, %W{
				Characteristics
				SizeOfOptionalHeader
				PointerToSymbolTable
				TimeDateStamp
				NumberOfSections
				Machine
			})
			$stdout.puts tbl.to_s
			$stdout.puts "\n\n"

			tbl = table("Optional Image Headers", ['Name', 'Value'])
			add_fields(tbl, pe.hdr.opt, %W{
				ImageBase
				Magic
				MajorLinkerVersion
				MinorLinkerVersion
				SizeOfCode
				SizeOfInitializeData
				SizeOfUninitializeData
				AddressOfEntryPoint
				BaseOfCode
				BaseOfData
				SectionAlignment
				FileAlignment
				MajorOperatingSystemVersion
				MinorOperatingSystemVersion
				MajorImageVersion
				MinorImageVersion
				MajorSubsystemVersion
				MinorSubsystemVersion
				Win32VersionValue
				SizeOfImage
				SizeOfHeaders
				CheckSum
				Subsystem
				DllCharacteristics
				SizeOfStackReserve
				SizeOfStackCommit
				SizeOfHeapReserve
				SizeOfHeapCommit
				LoaderFlags
				NumberOfRvaAndSizes
			})
			$stdout.puts tbl.to_s
			$stdout.puts "\n\n"
			
			tbl = table("Exported Functions", ['Ordinal', 'Name', 'Address'])
			pe.exports.entries.each do |ent|
				tbl << [ent.ordinal, ent.name, "0x%.8x" % pe.rva_to_vma(ent.rva)]
			end
			$stdout.puts tbl.to_s
			$stdout.puts "\n\n"

			tbl = table("Imported Functions", ['Library', 'Ordinal', 'Name'])
			pe.imports.each do |lib|
				lib.entries.each do |ent|
					tbl << [lib.name, ent.ordinal, ent.name]
				end
			end
			$stdout.puts tbl.to_s
			$stdout.puts "\n\n"
			
			if(pe.config)
				tbl = table("Configuration Header", ['Name', 'Value'])
				add_fields(tbl, pe.config, %W{			
					Size
					TimeDateStamp
					MajorVersion
					MinorVersion
					GlobalFlagsClear
					GlobalFlagsSet
					CriticalSectionDefaultTimeout
					DeCommitFreeBlockThreshold
					DeCommitTotalFreeThreshold
					LockPrefixTable
					MaximumAllocationSize
					VirtualMemoryThreshold
					ProcessAffinityMask
					ProcessHeapFlags
					CSDVersion
					Reserved1
					EditList
					SecurityCookie
					SEHandlerTable
					SEHandlerCount
				})
				$stdout.puts tbl.to_s
				$stdout.puts "\n\n"
			end


			tbl = table("Resources", ['Name', 'Language', 'Code Page', 'Size'])
			pe.resources.keys.sort.each do |rkey|
				res = pe.resources[rkey]
				tbl << [rkey, res.lang, res.code, res.size]
			end
			$stdout.puts tbl.to_s
			$stdout.puts "\n\n"
						
		end	
		
		def table(name, cols)
			Rex::Ui::Text::Table.new(
				'Header'  => name,
				'Columns' => cols
			)
		end
	end

# EOC

end
end
end
