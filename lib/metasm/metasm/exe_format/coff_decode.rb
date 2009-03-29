#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/exe_format/coff'
require 'metasm/decode'

module Metasm
class COFF
	class OptionalHeader
		# decodes a COFF optional header from coff.cursection
		# also decodes directories in coff.directory
		def decode(coff)
			super(coff)

			nrva = @numrva
			if @numrva > DIRECTORIES.length
				puts "W: COFF: Invalid directories count #{@numrva}" if $VERBOSE
				nrva = DIRECTORIES.length
			end

			coff.directory = {}
			DIRECTORIES[0, nrva].each { |dir|
				rva = coff.decode_word
				sz  = coff.decode_word
				if rva != 0 or sz != 0
					coff.directory[dir] = [rva, sz]
				end
			}
		end
	end

	class Section
		def decode(coff)
			super(coff)
			coff.decode_section_body(self)
		end
	end

	class ExportDirectory
		# decodes a COFF export table from coff.cursection
		def decode(coff)
			super(coff)

			if coff.sect_at_rva(@libname_p)
				@libname = coff.decode_strz
			end

			if coff.sect_at_rva(@func_p)
				@exports = []
				addrs = []
				@num_exports.times { |i| addrs << coff.decode_word }
				@num_exports.times { |i|
					e = Export.new
					e.ordinal = i + @ordinal_base
					addr = addrs[i]
					if addr >= coff.directory['export_table'][0] and addr < coff.directory['export_table'][0] + coff.directory['export_table'][1] and coff.sect_at_rva(addr)
						name = coff.decode_strz
						e.forwarder_lib, name = name.split('.', 2)
						if name[0] == ?#
							e.forwarder_ordinal = name[1..-1].to_i
						else
							e.forwarder_name = name
						end
					else
						e.target = addr
					end
					@exports << e
				}
			end
			if coff.sect_at_rva(@names_p)
				namep = []
				num_names.times { namep << coff.decode_word }
			end
			if coff.sect_at_rva(@ord_p)
				ords = []
				num_names.times { ords << coff.decode_half }
			end
			if namep and ords
				namep.zip(ords).each { |np, oi|
					@exports[oi].name_p = np
					if coff.sect_at_rva(np)
						@exports[oi].name = coff.decode_strz
					end
				}
			end
		end
	end

	class ImportDirectory
		# decodes all COFF import directories from coff.cursection
		def self.decode_all(coff)
			ret = []
			loop do
				idata = decode(coff)
				break if [idata.ilt_p, idata.libname_p, idata.iat_p].uniq == [0]
				ret << idata
			end
			ret.each { |idata| idata.decode_inner(coff) }
			ret
		end

		# decode the tables referenced
		def decode_inner(coff)
			if coff.sect_at_rva(@libname_p)
				@libname = coff.decode_strz
			end

			if coff.sect_at_rva(@ilt_p) || coff.sect_at_rva(@iat_p)
				addrs = []
				while (a_ = coff.decode_xword) != 0
					addrs << a_
				end

				@imports = []

				ord_mask = 1 << (coff.optheader.signature == 'PE+' ? 63 : 31)
				addrs.each { |a|
					i = Import.new
					if (a & ord_mask) != 0
						i.ordinal = a & (~ord_mask)
					else
						i.hintname_p = a
						if coff.sect_at_rva(a)
							i.hint = coff.decode_half
							i.name = coff.decode_strz
						end
					end
					@imports << i
				}
			end

			if coff.sect_at_rva(@iat_p)
				@iat = []
				while (a = coff.decode_xword) != 0
					@iat << a
				end
			end
		end
	end

	class ResourceDirectory
		def decode(coff, edata = coff.cursection.encoded, startptr = edata.ptr)
			super(coff)

			@entries = []

			nrnames = @nr_names if $DEBUG
			(@nr_names+@nr_id).times {
 				e = Entry.new

 				e_id = coff.decode_word(edata)
 				e_ptr = coff.decode_word(edata)

				tmp = edata.ptr

				if (e_id >> 31) == 1
					if $DEBUG
						nrnames -= 1
						puts "W: COFF: rsrc has invalid id #{id}" if nrnames < 0
					end
					e.name_p = e_id & 0x7fff_ffff
					edata.ptr = startptr + e.name_p
					namelen = coff.decode_half(edata)
					e.name_w = edata.read(2*namelen)
					if (chrs = e.name_w.unpack('v*')).all? { |c| c >= 0 and c <= 255 }
						e.name = chrs.pack('C*')
					end
				else
					if $DEBUG
						puts "W: COFF: rsrc has invalid id #{id}" if nrnames > 0
					end
					e.id = e_id
				end

				if (e_ptr >> 31) == 1	# subdir
					e.subdir_p = e_ptr & 0x7fff_ffff
					if startptr + e.subdir_p >= edata.length
						puts 'invalid resource structure: directory too far' if $VERBOSE
					else
						edata.ptr = startptr + e.subdir_p
						e.subdir = ResourceDirectory.new
						e.subdir.decode coff, edata, startptr
					end
				else
					e.dataentry_p = e_ptr
					edata.ptr = startptr + e.dataentry_p
					e.data_p = coff.decode_word(edata)
					sz = coff.decode_word(edata)
					e.codepage = coff.decode_word(edata)
					e.reserved = coff.decode_word(edata)

					if coff.sect_at_rva(e.data_p)
						e.data = coff.cursection.encoded.read(sz)
					end
				end

				edata.ptr = tmp
				@entries << e
			}
		end
	end

	class RelocationTable
		# decodes a relocation table from coff.encoded.ptr
		def decode(coff)
			super(coff)
			len = coff.decode_word
			len -= 8
			if len < 0 or len % 2 != 0
				puts "W: COFF: Invalid relocation table length #{len+8}" if $VERBOSE
				coff.cursection.encoded.read(len) if len > 0
				@relocs = []
				return
			end

			@relocs = coff.cursection.encoded.read(len).unpack(coff.endianness == :big ? 'n*' : 'v*').map { |r| Relocation.new(r&0xfff, r>>12) }
			#(len/2).times { @relocs << Relocation.decode(coff) }	# tables may be big, this is too slow
		end
	end

	class TLSDirectory
		def decode(coff)
			super(coff)

			if coff.sect_at_va(@callback_p)
				@callbacks = []
				while (ptr = coff.decode_xword) != 0
					# __stdcall void (*ptr)(void* dllhandle, dword reason, void* reserved)
					# (same as dll entrypoint)
					@callbacks << (ptr - coff.optheader.image_base)
				end
			end
		end
	end

	class LoadConfig
		def decode(coff)
			super(coff)

			if @sehcount >= 0 and @sehcount < 100 and (@signature == 0x40 or @signature == 0x48) and coff.sect_at_va(@sehtable_p)
				@safeseh = []
				@sehcount.times { @safeseh << coff.decode_xword }
			end
		end
	end

	class DelayImportDirectory
		def self.decode_all(coff)
			ret = []
			loop do
				didata = decode(coff)
				break if [didata.libname_p, didata.handle_p, didata.iat_p].uniq == [0]
				ret << didata
			end
			ret.each { |didata| didata.decode_inner(coff) }
			ret
		end

		def decode_inner(coff)
			if coff.sect_at_rva(@libname_p)
				@libname = coff.decode_strz
			end
			# TODO
		end
	end


	attr_accessor :cursection

	def decode_byte( edata = @cursection.encoded) ; edata.decode_imm(:u8,  @endianness) end
	def decode_half( edata = @cursection.encoded) ; edata.decode_imm(:u16, @endianness) end
	def decode_word( edata = @cursection.encoded) ; edata.decode_imm(:u32, @endianness) end
	def decode_xword(edata = @cursection.encoded) ; edata.decode_imm((@optheader.signature == 'PE+' ? :u64 : :u32), @endianness) end
	def decode_strz( edata = @cursection.encoded) ; if i = edata.data.index(?\0, edata.ptr) ; edata.read(i+1-edata.ptr).chop ; end ; end

	# converts an RVA (offset from base address of file when loaded in memory) to the section containing it using the section table
	# updates @cursection and @cursection.encoded.ptr to point to the specified address
	# may return self when rva points to the coff header
	# returns nil if none match, 0 never matches
	def sect_at_rva(rva)
		return if not rva or rva <= 0
		if sections and not @sections.empty?
			if s = @sections.find { |s_| s_.virtaddr <= rva and s_.virtaddr + s_.virtsize > rva }
				s.encoded.ptr = rva - s.virtaddr
				@cursection = s
			elsif rva < @sections.map { |s_| s_.virtaddr }.min
				@encoded.ptr = rva
				@cursection = self
			end
		elsif rva <= @encoded.length
			@encoded.ptr = rva
			@cursection = self
		end
	end

	def sect_at_va(va)
		sect_at_rva(va - @optheader.image_base)
	end

	def label_rva(name)
		if name.kind_of? Integer
			name
		elsif s = @sections.find { |s_| s_.encoded.export[name] }
			s.virtaddr + s.encoded.export[name]
		else
		       @encoded.export[name]
		end
	end

	def each_section
		base = @optheader.image_base
		base = 0 if not base.kind_of? Integer
		yield @encoded[0, @optheader.headers_size], base
		@sections.each { |s| yield s.encoded, base + s.virtaddr }
	end

	# decodes the COFF header, optional header, section headers
	# marks entrypoint and directories as edata.expord
	def decode_header
		@cursection ||= self
		@encoded.ptr ||= 0
		@header.decode(self)
		optoff = @encoded.ptr
		@optheader.decode(self)
		@cursection.encoded.ptr = optoff + @header.size_opthdr
		@header.num_sect.times { @sections << Section.decode(self) }
		if sect_at_rva(@optheader.entrypoint)
			@cursection.encoded.add_export new_label('entrypoint')
		end
		(DIRECTORIES - ['certificate_table']).each { |d|
			if @directory[d] and sect_at_rva(@directory[d][0])
				@cursection.encoded.add_export new_label(d)
			end
		}
	end

	# decodes a section content (allows simpler LoadedPE override)
	def decode_section_body(s)
		raw = EncodedData.align_size(s.rawsize, @optheader.file_align)
		virt = EncodedData.align_size(s.virtsize, @optheader.sect_align)
		s.encoded = @encoded[s.rawaddr, [raw, virt].min]
		s.encoded.virtsize = virt
	end

	# decodes COFF export table from directory
	# mark exported names as encoded.export
	def decode_exports
		if @directory['export_table'] and sect_at_rva(@directory['export_table'][0])
			@export = ExportDirectory.decode(self)
			@export.exports.to_a.each { |e|
				if e.name and sect_at_rva(e.target)
					name = e.name
				elsif e.ordinal and sect_at_rva(e.target)
					name = "ord_#{@export.libname}_#{e.ordinal}"
				end
				e.target = @cursection.encoded.add_export new_label(name) if name
			}
		end
	end

	# decodes COFF import tables from directory
	# mark iat entries as encoded.export
	def decode_imports
		if @directory['import_table'] and sect_at_rva(@directory['import_table'][0])
			@imports = ImportDirectory.decode_all(self)
			iatlen = (@optheader.signature == 'PE+' ? 8 : 4)
			@imports.each { |id|
				if sect_at_rva(id.iat_p)
					ptr = @cursection.encoded.ptr
					id.imports.each { |i|
						if i.name
							name = new_label i.name
						elsif i.ordinal
							name = new_label "ord_#{id.libname}_#{i.ordinal}"
						end
						if name
							r = Metasm::Relocation.new(Expression[name], :u32, @endianness)
							@cursection.encoded.reloc[ptr] = r
							@cursection.encoded.add_export new_label('iat_'+name), ptr, true
						end
						ptr += iatlen
					}
				end
			}
		end
	end

	# decodes resources from directory
	def decode_resources
		if @directory['resource_table'] and sect_at_rva(@directory['resource_table'][0])
			@resource = ResourceDirectory.decode(self)
		end
	end

	# decodes certificate table
	def decode_certificates
		if ct = @directory['certificate_table']
			@certificates = []
			@cursection = self
			@encoded.ptr = ct[0]
			off_end = ct[0]+ct[1]
			while @encoded.ptr < off_end
				certlen = decode_word
				certrev = decode_half
				certtype = decode_half
				certdat = @encoded.read(certlen)
				@certificates << [certrev, certtype, certdat]
			end
		end
	end

	# decode COFF relocation tables from directory
	def decode_relocs
		if @directory['base_relocation_table'] and sect_at_rva(@directory['base_relocation_table'][0])
			end_ptr = @cursection.encoded.ptr + @directory['base_relocation_table'][1]
			@relocations = []
			while @cursection.encoded.ptr < end_ptr
				@relocations << RelocationTable.decode(self)
			end

			# interpret as EncodedData relocations
			relocfunc = ('decode_reloc_' << @header.machine.downcase).to_sym
			if not respond_to? relocfunc
				puts "W: COFF: unsupported relocs for architecture #{@header.machine}" if $VERBOSE
				return
			end
			@relocations.each { |rt|
				rt.relocs.each { |r|
					if s = sect_at_rva(rt.base_addr + r.offset)
						e, p = s.encoded, s.encoded.ptr
						rel = send(relocfunc, r)
						e.reloc[p] = rel if rel
					end
				}
			}
		end
	end

	# decodes an I386 COFF relocation pointing to encoded.ptr
	def decode_reloc_i386(r)
		case r.type
		when 'ABSOLUTE'
		when 'HIGHLOW'
			addr = decode_word
			if s = sect_at_va(addr)
				label = label_at(s.encoded, s.encoded.ptr, 'xref_%04x' % addr)
				Metasm::Relocation.new(Expression[label], :u32, @endianness)
			end
		when 'DIR64'
			addr = decode_xword
			if s = sect_at_va(addr)
				label = label_at(s.encoded, s.encoded.ptr, 'xref_%04x' % addr)
				Metasm::Relocation.new(Expression[label], :u64, @endianness)
			end
		else puts "W: COFF: Unsupported i386 relocation #{r.inspect}" if $VERBOSE
		end
	end

	def decode_debug
		if dd = @directory['debug'] and sect_at_rva(dd[0])
			@debug = DebugDirectory.decode(self)
		end
	end

	# decode TLS directory, including tls callback table
	def decode_tls
		if @directory['tls_table'] and sect_at_rva(@directory['tls_table'][0])
			@tls = TLSDirectory.decode(self)
		       	if s = sect_at_va(@tls.callback_p)
				s.encoded.add_export 'tls_callback_table'
				@tls.callbacks.each_with_index { |cb, i|
					@tls.callbacks[i] = @cursection.encoded.add_export "tls_callback_#{i}" if sect_at_rva(cb)
			       	}
			end
		end
	end

	def decode_loadconfig
		if lc = @directory['load_config'] and sect_at_rva(lc[0])
			@loadconfig = LoadConfig.decode(self)
		end
	end

	def decode_delayimports
		if di = @directory['delay_import_table'] and sect_at_rva(di[0])
			@delayimports = DelayImportDirectory.decode_all(self)
		end
	end


	# decodes a COFF file (headers/exports/imports/relocs/sections)
	# starts at encoded.ptr
	def decode
		decode_header
		decode_exports
		decode_imports
		decode_resources
		decode_certificates
		decode_debug
		decode_tls
		decode_loadconfig
		decode_delayimports
		decode_relocs	# decode relocs last
	end

	# returns a metasm CPU object corresponding to +header.machine+
	def cpu_from_headers
		case @header.machine
		when 'I386'; Ia32.new
		when 'R4000'; MIPS.new(:little)
		else raise 'unknown cpu'
		end
	end

	# returns an array including the PE entrypoint and the exported functions entrypoints
	# TODO filter out exported data, include safeseh ?
	def get_default_entrypoints
		ep = []
		ep.concat @tls.callbacks.to_a if tls
		ep << (@optheader.image_base + label_rva(@optheader.entrypoint))
		@export.exports.each { |e|
			ep << (@optheader.image_base + label_rva(e.target)) if not e.forwarder_lib
		} if export
		ep
	end

	def dump_section_header(addr, edata)
		s = @sections.find { |s_| s_.virtaddr == addr-@optheader.image_base }
		s ? "\n.section #{s.name.inspect} base=#{Expression[addr]}" :
		addr == @optheader.image_base ? "// exe header at #{Expression[addr]}" : super(addr, edata)
	end
end

class COFFArchive
	class Member
		def decode(ar)
			@offset = ar.encoded.ptr

			super(ar)

			@name.strip!
			@date = @date.to_i
			@uid = @uid.to_i
			@gid = @gid.to_i
			@mode = @mode.to_i(8)
			@size = @size.to_i

			@encoded = ar.encoded[ar.encoded.ptr, @size]
			ar.encoded.ptr += @size
		end

		def decode_half ; @encoded.decode_imm(:u16, :big) end
		def decode_word ; @encoded.decode_imm(:u32, :big) end
	end

	def decode_half ; @encoded.decode_imm(:u16, :little) end
	def decode_word ; @encoded.decode_imm(:u32, :little) end
	def decode_strz(edata = @encoded) ; i = edata.data.index(?\0, edata.ptr) ; edata.read(i+1-ta.ptr).chop end

	def decode_first_linker
		offsets = []
		names = []
		m = @members[0]
		m.encoded.ptr = 0
		numsym = m.decode_word
		numsym.times { offsets << m.decode_word }
		numsym.times { names << decode_strz(m.encoded) }

		# names[42] is found in object at file offset offsets[42]
		# offsets are sorted by object index (all syms from 1st object, then 2nd etc)

		@first_linker = names.zip(offsets) #.inject({}) { |h, (n, o)| h.update n => o }
	end

	def decode_second_linker
		names = []
		mboffsets = []
		indices = []
		m = @members[1]
		m.encoded.ptr = 0
		nummb = m.decode_word
		nummb.times { mboffsets << m.decode_word }
		numsym = m.decode_word
		numsym.times { indices << m.decode_half }
		numsym.times { names << decode_strz(m.encoded) }

		# names[42] is found in object at file offset mboffsets[indices[42]]
		# symbols sorted by symbol name (supposed to be more efficient, but no index into string table...)

		#names.zip(indices).inject({}) { |h, (n, i)| h.update n => mboffsets[i] }
		@second_linker = [names, mboffsets, incides]
	end

	# set real name to archive members
	# look it up in the name table member if needed, or just remove the trailing /
	def fixup_names
		@members.each { |m|
			case m.name
			when '/'
			when '//'
			when /^\/(\d+)/
				@members[2].ptr = $1.to_i
				m.name = decode_strz(@members[2].encoded)
			else m.name.chomp! "/"
			end
		}
	end

	def decode
		@encoded.ptr = 0
		@signature = @encoded.read(8)
		raise InvalidExeFormat, "Invalid COFF Archive signature #{ar.signature.inspect}" if ar.signature != "!<arch>\n"
		@members = []
		while @encoded.ptr < @encoded.virtsize
			@members << Member.decode(self)
		end
		decode_first_linker
		decode_second_linker
		fixup_names
	end
end
end
