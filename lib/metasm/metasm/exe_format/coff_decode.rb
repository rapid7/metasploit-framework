#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/exe_format/coff'
require 'metasm/decode'

module Metasm
class COFF
	class Header
		# decodes a COFF header from coff.encoded.ptr
		def decode(coff)
			@machine  = coff.int_to_hash(coff.decode_half, MACHINE)
			@num_sect = coff.decode_half
			@time     = coff.decode_word
			@ptr_sym  = coff.decode_word
			@num_sym  = coff.decode_word
			@size_opthdr = coff.decode_half
			@characteristics = coff.bits_to_hash(coff.decode_half, CHARACTERISTIC_BITS)
		end
	end

	class OptionalHeader
		# decodes a COFF optional header from coff.encoded.ptr
		# also decodes directories in coff.directory
		def decode(coff)
			@signature  = coff.int_to_hash(coff.decode_half, SIGNATURE)
			@link_ver_maj = coff.decode_uchar
			@link_ver_min = coff.decode_uchar
			@code_size  = coff.decode_word 
			@data_size  = coff.decode_word 
			@udata_size = coff.decode_word
			@entrypoint = coff.decode_word
			@base_of_code = coff.decode_word
			@base_of_data = coff.decode_word if @signature != 'PE+'
			@image_base = coff.decode_xword
			@sect_align = coff.decode_word
			@file_align = coff.decode_word
			@os_ver_maj = coff.decode_half   
			@os_ver_min = coff.decode_half   
			@img_ver_maj= coff.decode_half  
			@img_ver_min= coff.decode_half  
			@subsys_maj = coff.decode_half
			@subsys_min = coff.decode_half
			@reserved   = coff.decode_word  
			@image_size = coff.decode_word
			@headers_size = coff.decode_word
			@checksum   = coff.decode_word
			@subsystem  = coff.int_to_hash(coff.decode_half, SUBSYSTEM)
			@dll_characts = coff.bits_to_hash(coff.decode_half, DLL_CHARACTERISTIC_BITS)
			@stack_reserve = coff.decode_xword
			@stack_commit = coff.decode_xword
			@heap_reserve = coff.decode_xword
			@heap_commit  = coff.decode_xword
			@ldrflags   = coff.decode_word
			@numrva     = coff.decode_word

			if @numrva > DIRECTORIES.length
				puts "W: COFF: Invalid directories count #{@numrva}"
				return self
			end

			coff.directory = {}
			DIRECTORIES[0, @numrva].each { |dir|
				rva = coff.decode_word
				sz  = coff.decode_word
				if rva != 0 or sz != 0
					coff.directory[dir] = [rva, sz]
				end
			}
		end
	end

	class Section
		# decodes a COFF section header from coff.encoded
		def decode(coff)
			@name = coff.encoded.read(8)
			@name = @name[0, @name.index(0)] if @name.index(0)
			@virtsize   = coff.decode_word
			@virtaddr   = coff.decode_word
			@rawsize    = coff.decode_word
			@rawaddr    = coff.decode_word
			@relocaddr  = coff.decode_word
			@linenoaddr = coff.decode_word
			@relocnr    = coff.decode_half
			@linenonr   = coff.decode_half
			@characteristics = coff.bits_to_hash(coff.decode_word, SECTION_CHARACTERISTIC_BITS)
		end
	end

	class ExportDirectory
		# decodes a COFF export table from coff.encoded.ptr
		def decode(coff)
			@reserved   = coff.decode_word
			@timestamp  = coff.decode_word
			@version_major = coff.decode_half
			@version_minor = coff.decode_half
			@libname_p  = coff.decode_word
			@ordinal_base  = coff.decode_word
			num_exports = coff.decode_word
			num_names   = coff.decode_word
			func_p     = coff.decode_word
			names_p    = coff.decode_word
			ord_p      = coff.decode_word

			if off = coff.rva_to_off(@libname_p)
				@libname = coff.encoded.data[off...coff.encoded.data.index(0, off)]
			end

			if coff.encoded.ptr = coff.rva_to_off(func_p)
				@exports = []
				num_exports.times { |i|
					e = Export.new
					e.ordinal = i + @ordinal_base
					addr = coff.decode_word
					if addr >= coff.directory['export_table'][0] and addr < coff.directory['export_table'][0] + coff.directory['export_table'][1] and off = coff.rva_to_off(addr)
						name = coff.encoded.data[off...coff.encoded.data.index(0, off)]
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
			if coff.encoded.ptr = coff.rva_to_off(names_p)
				namep = []
				num_names.times { namep << coff.decode_word }
			end
			if coff.encoded.ptr = coff.rva_to_off(ord_p)
				ords = []
				num_names.times { ords << coff.decode_half }
			end
			if namep and ords
				namep.zip(ords).each { |np, oi|
					@exports[oi].name_p = np
					if addr = coff.rva_to_off(np)
						@exports[oi].name = coff.encoded.data[addr...coff.encoded.data.index(0, addr)]
					end
				}
			end
		end
	end

	class ImportDirectory
		# decodes all COFF import directories from coff.encoded.ptr
		def self.decode(coff)
			ret = []
			loop do
				idata = new
				idata.decode(coff)
				break if not idata.imports
				ret << idata
			end
			ret
		end

		# decode a COFF import table from coff.encoded.ptr
		# after the function, coff.encoded.ptr points to the end of the import table
		def decode(coff)
			@ilt_p = coff.decode_word
			@timestamp = coff.decode_word
			@firstforwarder = coff.decode_word
			@libname_p = coff.decode_word
			@iat_p = coff.decode_word

			nextidata_ptr = coff.encoded.ptr	# will decode other directories

			return if [@ilt_p, @timestamp, @firstforwarder, @libname_p, @iat_p].all? { |p| p == 0 }

			if off = coff.rva_to_off(@libname_p)
				@libname = coff.encoded.data[off...coff.encoded.data.index(0, off)]
			end

			if coff.encoded.ptr = coff.rva_to_off(@ilt_p)
				addrs = []
				while (a = coff.decode_xword) != 0
					addrs << a
				end

				@imports = []
				
				ord_mask = 1 << (coff.optheader.signature == 'PE+' ? 63 : 31)
				addrs.each { |a|
					i = Import.new
					if (a & ord_mask) != 0
						i.ordinal = a & (~ord_mask)
					else
						i.hintname_p = a
						if coff.encoded.ptr = coff.rva_to_off(a)
							i.hint = coff.decode_half
							i.name = coff.encoded.data[coff.encoded.ptr...coff.encoded.data.index(0, coff.encoded.ptr)]
						end
					end
					@imports << i
				}
			end

			if coff.encoded.ptr = coff.rva_to_off(@iat_p)
				@iat = []
				while (a = coff.decode_xword) != 0
					@iat << a
				end
			end

			coff.encoded.ptr = nextidata_ptr
		end
	end

	class DelayImportDirectory
		def self.decode(coff)
			ret = []
			loop do
				didata = new
				didata.decode coff
				break if didata.empty?
				ret << didata
			end
			ret
		end

		def decode(coff)
			@attributes = coff.decode_word
			@libname_p = coff.decode_word
			@handle_p = coff.decode_word	# the loader stores the handle at the location pointed by this field at runtime
			@diat_p  = coff.decode_word
			@dint_p  = coff.decode_word
			@bdiat_p = coff.decode_word
			@udiat_p = coff.decode_word
			@timestamp = coff.decode_word

			saved_ptr = coff.encoded.ptr

			if off = coff.rva_to_off(@libname_p)
				@libname = coff.encoded.data[off...coff.encoded.data.index(0, off)]
			end

			coff.encoded.ptr = saved_ptr
		end
	end

	class RelocationTable
		# decodes a relocation table from coff.encoded.ptr
		def decode(coff)
			@base_addr = coff.decode_word
			@relocs = []
			len = coff.decode_word
			if len < 8 or len % 2 != 0
				puts "W: COFF: Invalid relocation table length #{len}"
				return
			end
			len -= 8
			len /= 2
			len.times {
				raw = coff.decode_half
				r = Relocation.new
				r.offset = raw & 0xfff
				r.type = coff.int_to_hash(((raw >> 12) & 15), BASE_RELOCATION_TYPE)
				@relocs << r
			}
		end
	end

	class ResourceDirectory
		def decode(coff, startoff = coff.encoded.ptr)
			@characteristics = coff.decode_word
			@timestamp = coff.decode_word
			@major_version = coff.decode_half
			@minor_version = coff.decode_half
			nrnames = coff.decode_half
			nrid = coff.decode_half
			@entries = []

			(nrnames+nrid).times {
				e = Entry.new
				id  = coff.decode_word
				ptr = coff.decode_word

				saved_ptr = coff.encoded.ptr

				if (id >> 31) == 1
					if $DEBUG
						nrnames -= 1
						puts "W: COFF: rsrc has invalid id #{id}" if nrnames < 0
					end
					e.name_p = id & 0x7fff_ffff
					coff.encoded.ptr = startoff + e.name_p
					namelen = coff.decode_half
					e.name_w = coff.encoded.read(2*namelen)
					if (chrs = e.name_w.unpack('v*')).all? { |c| c <= 255 }
						e.name = chrs.pack('C*')
					end
				else
					if $DEBUG
						puts "W: COFF: rsrc has invalid id #{id}" if nrnames > 0
					end
					e.id = id
				end

				if (ptr >> 31) == 1	# subdir
					e.subdir_p = ptr & 0x7fff_ffff
					coff.encoded.ptr = startoff + e.subdir_p
					e.subdir = ResourceDirectory.new
					e.subdir.decode coff, startoff
				else
					e.dataentry_p = ptr
					coff.encoded.ptr = startoff + e.dataentry_p
					e.data_p = coff.decode_word
					sz = coff.decode_word
					e.codepage = coff.decode_word
					e.reserved = coff.decode_word

					if coff.encoded.ptr = coff.rva_to_off(e.data_p)
						e.data = coff.encoded.read(sz)
					end
				end

				@entries << e

				coff.encoded.ptr = saved_ptr
			}
		end
	end

	class DebugDirectory
		def decode(coff)
			@characteristics = coff.decode_word
			@timestamp = coff.decode_word
			@major_version = coff.decode_half
			@minor_version = coff.decode_half
			@type = coff.int_from_hash(coff.decode_word, DEBUG_TYPE)
			@size_of_data = coff.decode_word
			@addr = coff.decode_word
			@pointer = coff.decode_word
		end
	end

	class TLSDirectory
		def decode(coff)
			@start_va = coff.decode_xword	# must have a .reloc
			@end_va = coff.decode_xword
			@index_addr = coff.decode_xword	# va ? rva ?
			@callback_p = coff.decode_xword	# ptr to 0-terminated x?word callback ptrs
			@zerofill_sz = coff.decode_word	# nr of 0 bytes to append to the template (start_va)
			@characteristics = coff.decode_word

			if coff.encoded.ptr = coff.rva_to_off(@callback_p)
				@callbacks = []
				while (ptr = coff.decode_xword) != 0
					# void NTAPI (*ptr)(void* dllhandle, dword reason, void* reserved)
					# (same as dll entrypoint)
					@callbacks << ptr
				end
			end
		end
	end

	class LoadConfig
		def decode(coff)
			@signature = coff.decode_word
			@timestamp = coff.decode_word
			@major_version = coff.decode_half
			@minor_version = coff.decode_half
			@globalflags = coff.decode_word
			@critsec_timeout = coff.decode_word
			@decommitblock = coff.decode_xword
			@decommittotal = coff.decode_xword
			@lockpfxtable = coff.decode_xword	# VA of ary of instruction using LOCK prefix, to be nopped on singleproc machine (wtf?)
			@maxalloc = coff.decode_xword
			@maxvirtmem = coff.decode_xword
			@process_affinity_mask = coff.decode_xword
			@process_heap_flags = coff.decode_word
			@servicepackid = coff.decode_half
			@reserved = coff.decode_half
			@editlist = coff.decode_xword
			@security_cookie = coff.decode_xword
			@sehtable_p = coff.decode_xword	# VA
			@sehcount = coff.decode_xword

			# @sehcount is really the count ?
			if @sehcount >= 0 and @sehcount < 100 and (@signature == 0x40 or @signature == 0x48) and coff.encoded.ptr = coff.rva_to_off(@sehtable_p - coff.optheader.image_base)
				@safeseh = []
				@sehcount.times { @safeseh << coff.decode_xword }
			end
		end
	end


	def decode_uchar(edata = @encoded) ; edata.decode_imm(:u8,  @endianness) end
	def decode_half( edata = @encoded) ; edata.decode_imm(:u16, @endianness) end
	def decode_word( edata = @encoded) ; edata.decode_imm(:u32, @endianness) end
	def decode_xword(edata = @encoded) ; edata.decode_imm((@optheader.signature == 'PE+' ? :u64 : :u32), @endianness) end

	# converts an RVA (offset from base address of file when loaded in memory) to an offset in the file, using the section table
	# may not work with overlapping sections and the like
	def rva_to_off rva
		s = @sections.find { |s| s.virtaddr <= rva and s.virtaddr + s.virtsize > rva } if rva and rva != 0
		if s
			rva - s.virtaddr + s.rawaddr
		elsif rva > 0 and rva < @optheader.headers_size
			rva
		end
	end

	def each_section
		base = @optheader.image_base
		base = 0 if not base.kind_of? Integer
		yield @encoded[0, @optheader.headers_size], base
		@sections.each { |s| yield s.encoded, base + s.virtaddr }
	end

	# decodes the COFF header, optional header, section headers
	# marks entrypoint and directories as encoded.export
	def decode_header
		@header.decode(self)
		@optheader.decode(self)
		@header.num_sect.times {
			s = Section.new
			s.decode self
			@sections << s
		}
		if off = rva_to_off(@optheader.entrypoint)
			@encoded.export[new_label('entrypoint')] = off
		end
		(DIRECTORIES - ['certificate_table']).each { |d|
			if @directory and @directory[d] and off = rva_to_off(@directory[d][0])
				@encoded.export[new_label(d)] = off
			end
		}
	end

	# decodes COFF export table from directory
	# mark exported names as encoded.export
	def decode_exports
		if @directory and @directory['export_table'] and @encoded.ptr = rva_to_off(@directory['export_table'][0])
			@export = ExportDirectory.new
			@export.decode(self)
			@export.exports.each { |e|
				if e.name and off = rva_to_off(e.target)
					@encoded.export[e.name] = off
				end
			} if @export.exports
		end
	end

	# decodes COFF import tables from directory
	# mark iat entries as encoded.export
	def decode_imports
		if @directory and @directory['import_table'] and @encoded.ptr = rva_to_off(@directory['import_table'][0])
			@imports = ImportDirectory.decode(self)
			iatlen = @optheader.signature == 'PE+' ? 8 : 4
			@imports.each { |id|
				if off = rva_to_off(id.iat_p)
					id.imports.each_with_index { |i, idx|
						@encoded.export[i.name] = off + iatlen*idx if i.name
					}
				end
			}
		end
	end

	# decode COFF relocation tables from directory
	# mark relocations as encoded.relocs
	def decode_relocs
		if @directory and @directory['base_relocation_table'] and @encoded.ptr = rva_to_off(@directory['base_relocation_table'][0])
			end_addr = @encoded.ptr + @directory['base_relocation_table'][1]
			@relocations = []
			while @encoded.ptr < end_addr
				rt = RelocationTable.new
				rt.decode self
				@relocations << rt
			end

			# interpret as EncodedData relocations
			relocfunc = ('decode_reloc_' << @header.machine.downcase).to_sym
			if not respond_to? relocfunc
				puts "W: COFF: unsupported relocs for architecture #{@header.machine}"
				return
			end
			@relocations.each { |rt|
				rt.relocs.each { |r|
					if off = rva_to_off(rt.base_addr + r.offset)
						@encoded.ptr = off
						rel = send(relocfunc, r)
						@encoded.reloc[off] = rel if rel
					end
				}
			}
		end
	end

	# decodes an I386 COFF relocation pointing to encoded.ptr
	def decode_reloc_i386(r)
		case r.type
		when 'ABSOLUTE'
		when 'HIGHLOW', 'DIR64'
			case r.type
			when 'HIGHLOW': addr, type = decode_word, :u32
			when 'DIR64':   addr, type = decode_xword, :u64
			end
			addr -= @optheader.image_base
			if off = rva_to_off(addr)
				Metasm::Relocation.new(Expression[label_at(@encoded, off, 'xref_%x' % addr)], type, @endianness)
			end
		else puts "W: COFF: Unsupported i386 relocation #{r.inspect}"
		end
	end

	# decodes resources from directory
	def decode_resources
		if @directory and @directory['resource_table'] and @encoded.ptr = rva_to_off(@directory['resource_table'][0])
			@resource = ResourceDirectory.new
			@resource.decode self
		end
	end

	# decodes certificate table
	def decode_certificates
		if @directory and ct = @directory['certificate_table']
			@encoded.ptr = ct[0]
			@certificates = (0...(ct[1]/8)).map { @encoded.data[decode_word, decode_word] }
		end
	end

	def decode_loadconfig
		if @directory and lc = @directory['load_config'] and @encoded.ptr = rva_to_off(lc[0])
			@loadconfig = LoadConfig.new
			@loadconfig.decode(self)
		end
	end

	# read section data
	def decode_sections
		@sections.each { |s|
			s.encoded = @encoded[s.rawaddr, [s.rawsize, s.virtsize].min]
			s.encoded.virtsize = s.virtsize
		}
	end

	# decodes a COFF file (headers/exports/imports/relocs/sections)
	# starts at encoded.ptr
	def decode
		decode_header
		decode_exports
		decode_imports
		decode_resources
		decode_certificates
		decode_relocs
		decode_sections
	end
end

class COFFArchive
	def self.decode(str)
		ar = new
		ar.encoded = EncodedData.new << str
		ar.signature = ar.encoded.read(8)
		raise InvalidExeFormat, "Invalid COFF Archive signature #{ar.signature.inspect}" if ar.signature != "!<arch>\n"
		ar.members = []
		while ar.encoded.ptr < ar.encoded.virtsize
			ar.decode_member
		end
		ar.decode_first_linker
		ar.decode_second_linker
		ar.fixup_names
		ar
	end

	class Member
		def decode(ar)
			@offset = ar.encoded.ptr
			@name = ar.encoded.read(16).strip
			@date = ar.encoded.read(12).to_i
			@uid = ar.encoded.read(6).to_i
			@gid = ar.encoded.read(6).to_i
			@mode = ar.encoded.read(8).to_i 8
			@size = ar.encoded.read(10).to_i
			@eoh = ar.read(2)	# should be <'\n>
		end
	end

	class ImportHeader
		def decode(ar)
			@sig1 = ar.encoded.decode_imm(:u16, :little)
			@sig2 = ar.encoded.decode_imm(:u16, :little)
			@version = ar.encoded.decode_imm(:u16, :little)
			@machine = ar.encoded.decode_imm(:u16, :little)
			@timestamp = ar.encoded.decode_imm(:u32, :little)
			@size_of_data = ar.encoded.decode_imm(:u32, :little)
			@hint = ar.encoded.decode_imm(:u16, :little)
			type = ar.encoded.decode_imm(:u16, :little)
			@type = ar.int_from_hash((type >> 14) & 3, IMPORT_TYPE)
			@name_type = ar.int_from_hash((type >> 11) & 7, NAME_TYPE)
			@reserved = type & 0x7ff
			@symname = ar.encoded.data[ar.encoded.ptr...ar.encoded.data.index(0, ar.encoded.ptr)]
			ar.encoded.ptr += @symname.length + 1
			@libname = ar.encoded.data[ar.encoded.ptr...ar.encoded.data.index(0, ar.encoded.ptr)]
		end
	end

	def decode_member_header
		h = Member.new
		h.decode self
		@members << h
	end

	def decode_member
		decode_member_header
		m = @members.last
		m.encoded = @encoded[@encoded.ptr, m.size]
		@encoded.ptr += m.size
	end

	def decode_first_linker
		m = @members[0]
		m.encoded.ptr = 0
		numsym = m.encoded.decode_imm(:u32, :big)
		offsets = []
		numsym.times { offsets << m.encoded.decode_imm(:u32, :big) }
		names = []
		numsym.times {
			names << ''
			while (c = m.encoded.get_byte) != 0
				names.last << c
			end
		}
		# names[42] is found in object at file offset offsets[42]
		# offsets are sorted by object index (all syms from 1st object, then 2nd etc)
		@first_linker = names.zip(offsets).inject({}) { |h, (n, o)| h.update n => o }
	end

	def decode_second_linker
		m = @members[1]
		m.encoded.ptr = 0
		nummb = m.encoded.decode_imm(:u32, :big)
		mboffsets = []
		nummb.times { mboffsets << m.encoded.decode_imm(:u32, :big) }
		numsym = m.encoded.decode_imm(:u32, :big)
		indices = []
		numsym.times { indices << m.encoded.decode_imm(:u16, :big) }
		names = []
		numsym.times {
			names << ''
			while (c = m.encoded.get_byte) != 0
				names.last << c
			end
		}
		# names[42] is found in object at file offset mboffsets[indices[42]]
		# symbols sorted by symbol name (supposed to be more efficient, but no index into string table...)
		@second_linker = names.zip(indices).inject({}) { |h, (n, i)| h.update n => mboffsets[i] }
	end

	# set real name to archive members: look it up in the name table member if needed, or just remove the trailing /
	def fixup_names
		@members.each { |m|
			case m.name
			when '/'
			when '//'
			when /\/(\d+)/
				m.name = @members[2].encoded.data[$1.to_i, @members[2].size]
				m.name = m.name[0, m.name.index(0)]
			else m.name.chomp! "/"
			end
		}
	end
end
end
