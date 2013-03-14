# -*- coding: binary -*-
require 'metasm'

module Rex
module PeScan
module Scanner

	class Generic

		attr_accessor :pe, :regex

		def initialize(pe)
			self.pe = pe
		end

		def config(param)
		end

		def scan(param)
			config(param)

			$stdout.puts "[#{param['file']}]"
			pe.all_sections.each do |section|
				hits = scan_section(section, param)
				hits.each do |hit|
					vma  = pe.rva_to_vma(hit[0])

					next if (param['filteraddr'] and [vma].pack("V").reverse !~ /#{param['filteraddr']}/)

					msg  = hit[1].is_a?(Array) ? hit[1].join(" ") : hit[1]
					$stdout.puts pe.ptr_s(vma) + " " + msg
					if(param['disasm'])
						#puts [msg].pack('H*').inspect
						insns = []

						msg.gsub!("; ", "\n")
						if msg.include?("retn")
							msg.gsub!("retn", "ret")
						end
						#puts msg
						begin
							d2 = Metasm::Shellcode.assemble(Metasm::Ia32.new, msg).disassemble
						rescue Metasm::ParseError
							d2 = Metasm::Shellcode.disassemble(Metasm::Ia32.new, [msg].pack('H*'))
						end
						addr = 0
						while ((di = d2.disassemble_instruction(addr)))
							insns << di.instruction
							disasm = "0x%08x\t" % (vma + addr)
							disasm << di.instruction.to_s
							$stdout.puts disasm
							addr = di.next_addr
						end
#						::Rex::Assembly::Nasm.disassemble([msg].pack("H*")).split("\n").each do |line|
#							$stdout.puts "\tnasm: #{line.strip}"
						#end
					end
				end
			end
		end

		def scan_section(section, param={})
			[]
		end
	end

	class JmpRegScanner < Generic

		def config(param)
			regnums = param['args']

			# build a list of the call bytes
			calls  = _build_byte_list(0xd0, regnums - [4]) # note call esp's don't work..
			jmps   = _build_byte_list(0xe0, regnums)
			pushs1 = _build_byte_list(0x50, regnums)
			pushs2 = _build_byte_list(0xf0, regnums)

			regexstr = '('
			if !calls.empty?
				regexstr += "\xff[#{calls}]|"
			end

			regexstr += "\xff[#{jmps}]|([#{pushs1}]|\xff[#{pushs2}])(\xc3|\xc2..))"

			self.regex = Regexp.new(regexstr, nil, 'n')
		end

		# build a list for regex of the possible bytes, based on a base
		# byte and a list of register numbers..
		def _build_byte_list(base, regnums)
			regnums.collect { |regnum| Regexp.escape((base | regnum).chr) }.join('')
		end

		def _ret_size(section, index)
			d = section.read(index, 1)
			case d
				when "\xc3"
					return 1
				when "\xc2"
					return 3
			end

			raise RuntimeError, "invalid return opcode"
		end

		def _parse_ret(data)
			if data.length == 1
				return "ret"
			else
				return "retn 0x%04x" % data[1, 2].unpack('v')[0]
			end
		end


		def scan_section(section, param={})
			index = 0

			hits  = [ ]

			while (index = section.index(regex, index)) != nil
				rva     = section.offset_to_rva(index)
				message = ''

				parse_ret = false

				byte1 = section.read(index, 1).unpack("C*")[0]

				if byte1 == 0xff
					byte2   = section.read(index+1, 1).unpack("C*")[0]
					regname = Rex::Arch::X86.reg_name32(byte2 & 0x7)

					case byte2 & 0xf8
					when 0xd0
						message = "call #{regname}"
						index += 2
					when 0xe0
						message = "jmp #{regname}"
						index += 2
					when 0xf0
						retsize = _ret_size(section, index+2)
						message = "push #{regname}; " + _parse_ret(section.read(index+2, retsize))
						index += 2 + retsize
					else
						raise "wtf"
					end
				else
					regname = Rex::Arch::X86.reg_name32(byte1 & 0x7)
					retsize = _ret_size(section, index+1)
					message = "push #{regname}; " + _parse_ret(section.read(index+1, retsize))
					index += 1 + retsize
				end

				hits << [ rva, message ]
			end

			return hits
		end
	end

	class PopPopRetScanner < JmpRegScanner

		def config(param)
			pops = _build_byte_list(0x58, (0 .. 7).to_a - [4]) # we don't want pop esp's...
			self.regex = Regexp.new("[#{pops}][#{pops}](\xc3|\xc2..)", nil, 'n')
		end

		def scan_section(section, param={})

			index = 0

			hits  = [ ]

			while index < section.size && (index = section.index(regex, index)) != nil
				rva     = section.offset_to_rva(index)
				message = ''

				pops = section.read(index, 2)
				reg1 = Rex::Arch::X86.reg_name32(pops[0,1].unpack("C*")[0] & 0x7)
				reg2 = Rex::Arch::X86.reg_name32(pops[1,1].unpack("C*")[0] & 0x7)

				message = "pop #{reg1}; pop #{reg2}; "

				retsize = _ret_size(section, index+2)
				message += _parse_ret(section.read(index+2, retsize))

				index += 2 + retsize

				hits << [ rva, message ]
			end

			return hits
		end
	end

	class RegexScanner < Generic

		def config(param)
			self.regex = Regexp.new(param['args'], nil, 'n')
		end

		def scan_section(section, param={})
			index = 0

			hits  = [ ]

			while index < section.size && (index = section.index(regex, index)) != nil

				idx = index
				buf = ''
				mat = nil

				while (! (mat = buf.match(regex)))
					buf << section.read(idx, 1)
					idx += 1
				end

				rva = section.offset_to_rva(index)

				hits << [ rva, buf.unpack("H*") ]
				index += buf.length
			end

			return hits
		end
	end

end
end
end

