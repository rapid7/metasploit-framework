#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/decode'
require 'metasm/exe_format/elf'

module Metasm
class ELF
	class Header
		# decodes the elf header, pointed to by elf.encoded.ptr
		def decode elf
			@ident = elf.encoded.read 16

			@magic = @ident[0, 4]
			raise InvalidExeFormat, "E: ELF: invalid ELF signature #{@magic.inspect}" if @magic != "\x7fELF"

			@e_class = elf.int_to_hash(@ident[4], CLASS)
			case @e_class
			when '32'; elf.bitsize = 32
			when '64', '64_icc'; elf.bitsize = 64
			else raise InvalidExeFormat, "E: ELF: unsupported class #{@e_class}"
			end

			@data = elf.int_to_hash(@ident[5], DATA)
			case @data
			when 'LSB'; elf.endianness = :little
			when 'MSB'; elf.endianness = :big
			else raise InvalidExeFormat, "E: ELF: unsupported endianness #{@data}"
			end

			# from there we can use elf.decode_word etc
			@version = elf.int_to_hash(@ident[6], VERSION)
			case @version
			when 'CURRENT'
			else raise "E: ELF: unsupported ELF version #{@version}"
			end

			@abi = elf.int_to_hash(@ident[7], ABI)
			@abi_version = @ident[8]

			# decodes the architecture-dependant part
			@type      = elf.int_to_hash(elf.decode_half, TYPE)
			@machine   = elf.int_to_hash(elf.decode_half, MACHINE)
			@version   = elf.int_to_hash(elf.decode_word, VERSION)
			@entry     = elf.decode_addr
			@phoff     = elf.decode_off
			@shoff     = elf.decode_off
			@flags     = elf.bits_to_hash(elf.decode_word, FLAGS[@machine])
			@ehsize    = elf.decode_half
			@phentsize = elf.decode_half
			@phnum     = elf.decode_half
			@shentsize = elf.decode_half
			@shnum     = elf.decode_half
			@shstrndx  = elf.decode_half
		end
	end

	class Section
		# decodes the section header pointed to by elf.encoded.ptr
		def decode elf
			@name_p    = elf.decode_word
			@type      = elf.int_to_hash(elf.decode_word, SH_TYPE)
			@flags     = elf.bits_to_hash(elf.decode_xword, SH_FLAGS)
			@addr      = elf.decode_addr
			@offset    = elf.decode_off
			@size      = elf.decode_xword
			@link      = elf.decode_word
			@info      = elf.decode_word
			@addralign = elf.decode_xword
			@entsize   = elf.decode_xword
		end
	end

	class Segment
		# decodes the program header pointed to by elf.encoded.ptr
		def decode elf
			@type   = elf.int_to_hash(elf.decode_word, PH_TYPE)
			@flags  = elf.bits_to_hash(elf.decode_word, PH_FLAGS) if elf.bitsize == 64
			@offset = elf.decode_off
			@vaddr  = elf.decode_addr
			@paddr  = elf.decode_addr
			@filesz = elf.decode_xword
			@memsz  = elf.decode_xword
			@flags  = elf.bits_to_hash(elf.decode_word, PH_FLAGS) if elf.bitsize == 32
			@align  = elf.decode_xword
		end
	end

	class Symbol
		# decodes the symbol pointed to by elf.encoded.ptr
		# read the symbol name from strtab
		def decode elf, strtab=nil
			case elf.bitsize
			when 32
				@name_p = elf.decode_word
				@value  = elf.decode_addr
				@size   = elf.decode_word
				set_info(elf, elf.decode_uchar)
				@other  = elf.decode_uchar
				@shndx  = elf.int_to_hash(elf.decode_half, SH_INDEX)
			when 64
				@name_p = elf.decode_word
				set_info(elf, elf.decode_uchar)
				@other  = elf.decode_uchar
				@shndx  = elf.int_to_hash(elf.decode_half, SH_INDEX)
				@value  = elf.decode_addr
				@size   = elf.decode_xword
			end

			@name = elf.readstr(strtab, @name_p) if strtab
		end
	end

	class Relocation
		# decodes the relocation with no explicit addend pointed to by elf.encoded.ptr
		# the symbol is taken from ary if possible, and is set to nil for index 0
		def decode(elf, symtab)
			@offset = elf.decode_addr
			set_info(elf, elf.decode_xword, symtab)
		end

		# same as +decode+, but with explicit addend (RELA)
		def decode_addend(elf, symtab)
			decode(elf, symtab)
			@addend = elf.decode_sxword
		end
	end

	# basic immediates decoding functions
	def decode_uchar(edata = @encoded) edata.decode_imm(:u8,  @endianness) end
	def decode_half( edata = @encoded) edata.decode_imm(:u16, @endianness) end
	def decode_word( edata = @encoded) edata.decode_imm(:u32, @endianness) end
	def decode_sword(edata = @encoded) edata.decode_imm(:i32, @endianness) end
	def decode_xword(edata = @encoded) edata.decode_imm((@bitsize == 32 ? :u32 : :u64), @endianness) end
	def decode_sxword(edata= @encoded) edata.decode_imm((@bitsize == 32 ? :i32 : :i64), @endianness) end
	alias decode_addr decode_xword
	alias decode_off  decode_xword

	def readstr(str, off)
		if off > 0 and i = str.index(0, off) rescue false	# LoadedElf with arbitrary pointer...
			str[off...i]
		end
	end

	# transforms a virtual address to a file offset, from mmaped segments addresses
	def addr_to_off addr
		s = @segments.find { |s| s.type == 'LOAD' and s.vaddr <= addr and s.vaddr + s.memsz > addr } if addr
		addr - s.vaddr + s.offset if s
	end

	# make an export of +self.encoded+, returns the label name if successful
	def add_label(name, addr)
		if not o = addr_to_off(addr)
			puts "W: Elf: #{name} points to unmmaped space #{'0x%08X' % addr}" if $VERBOSE
		else
			l = new_label(name)
			@encoded.add_export l, o
		end
		l
	end

	# decodes the elf header, section & program header
	def decode_header(off = 0)
		@encoded.ptr = off
		@header.decode self
		raise InvalidExeFormat, "Invalid elf header size: #{@header.ehsize}" if Header.size(self) != @header.ehsize
		if @header.phoff != 0
			decode_program_header(@header.phoff+off)
		end
		if @header.shoff != 0
			decode_section_header(@header.shoff+off)
		end
	end

	# decodes the section header
	# section names are read from shstrndx if possible
	def decode_section_header(off = @header.shoff)
		raise InvalidExeFormat, "Invalid elf section header size: #{@header.shentsize}" if Section.size(self) != @header.shentsize
		@encoded.add_export new_label('section_header'), off
		@encoded.ptr = off
		@sections.clear
		@header.shnum.times {
			s = Section.new
			s.decode(self)
			@sections << s
		}
		
		# read sections name
		if @header.shstrndx != 0 and str = @sections[@header.shstrndx] and str.encoded = @encoded[str.offset, str.size]
			# LoadedElf may not have shstr mmaped
			@sections[1..-1].each { |s|
				s.name = readstr(str.encoded.data, s.name_p)
				add_label("section_#{s.name}", s.addr) if s.name and s.addr > 0
			}
		end
	end

	# decodes the program header table
	# marks the elf entrypoint as an export of +self.encoded+
	def decode_program_header(off = @header.phoff)
		raise InvalidExeFormat, "Invalid elf program header size: #{@header.phentsize}" if Segment.size(self) != @header.phentsize
		@encoded.add_export new_label('program_header'), off
		@encoded.ptr = off
		@segments.clear
		@header.phnum.times {
			s = Segment.new
			s.decode(self)
			@segments << s
		}

		if @header.entry != 0
			add_label('entrypoint', @header.entry)
		end
	end

	# read the dynamic symbols hash table, and checks that every global and named symbol is accessible through it
	# outputs a warning if it's not and $VERBOSE is set
	def check_symbols_hash(off = @tag['HASH'])
		return if not @encoded.ptr = off

		hash_bucket_len = decode_word
		sym_count = decode_word

		hash_bucket = [] ; hash_bucket_len.times { hash_bucket << decode_word }
		hash_table = [] ; sym_count.times { hash_table << decode_word }

		@symbols.each { |s|
			next if not s.name or s.bind != 'GLOBAL' or s.shndx == 'UNDEF'

			found = false
			h = ELF.hash_symbol_name(s.name)
			off = hash_bucket[h % hash_bucket_len]
			sym_count.times {	# to avoid DoS by loop
				break if off == 0
				if ss = @symbols[off] and ss.name == s.name
					found = true
					break
				end
				off = hash_table[off]
			}
			if not found
				puts "W: Elf: Symbol #{s.name.inspect} not found in hash table" if $VERBOSE
			end
		}
	end

	# checks every symbol's accessibility through the gnu_hash table
	def check_symbols_gnu_hash(off = @tag['GNU_HASH'])
		return if not @encoded.ptr = off

		# when present: the symndx first symbols are not sorted (SECTION/LOCAL/FILE/etc) symtable[symndx] is sorted (1st sorted symbol)
		# the sorted symbols are sorted by [gnu_hash_symbol_name(symbol.name) % hash_bucket_len]
		hash_bucket_len = decode_word
		symndx = decode_word		# index of first sorted symbol in symtab
		maskwords = decode_word		# number of words in the second part of the ghash section (32 or 64 bits)
		shift2 = decode_word		# used in the bloom filter

		bloomfilter = [] ; maskwords.times { bloomfilter << decode_xword }
		# "bloomfilter[N] has bit B cleared if there is no M (M > symndx) which satisfies (C = @header.class)
		# ((gnu_hash(sym[M].name) / C) % maskwords) == N	&&
		# ((gnu_hash(sym[M].name) % C) == B			||
		# ((gnu_hash(sym[M].name) >> shift2) % C) == B"
		# bloomfilter may be [~0]

		hash_bucket = [] ; hash_bucket_len.times { hash_bucket << decode_word }
		# bucket[N] contains the lowest M for which
		# gnu_hash(sym[M]) % nbuckets == N
		# or 0 if none
			
		symcount = 0			# XXX how do we get symcount ?
		part4 = [] ; (symcount - symndx).times { part4 << decode_word }
		# part4[N] contains
		# (gnu_hash(sym[N].name) & ~1) | (N == dynsymcount-1 || (gnu_hash(sym[N].name) % nbucket) != (gnu_hash(sym[N+1].name) % nbucket))
		# that's the hash, with its lower bit replaced by the bool [1 if i am the last sym having my hash as hash]

		# TODO
	end

	# read dynamic tags array
	def decode_tags(off = nil)
		if not off
			if s = @segments.find { |s| s.type == 'DYNAMIC' }
				# this way it also works with LoadedELF
				off = addr_to_off(s.vaddr)
			elsif s = @sections.find { |s| s.type == 'DYNAMIC' }
				# if no DYNAMIC segment, assume we decode an ET_REL from file
				off = s.offset
			end
		end
		return if not @encoded.ptr = off

		@tag = {}
		loop do
			tag = decode_sxword
			val = decode_xword
			case tag = int_to_hash(tag, DYNAMIC_TAG)
			when 'NULL'
				@tag[tag] = val
				break
			when Integer
				puts "W: Elf: unknown dynamic tag 0x#{tag.to_s 16}" if $VERBOSE
				@tag[tag] ||= []
				@tag[tag] << val
			when 'NEEDED'		# here, list of tags for which multiple occurences are allowed
				@tag[tag] ||= []
				@tag[tag] << val
			when 'POSFLAG_1'
				puts "W: Elf: ignoring dynamic tag modifier #{tag} #{int_to_hash(val, DYNAMIC_POSFLAG_1)}" if $VERBOSE
			else
				if @tag[tag]
					puts "W: Elf: ignoring re-occurence of dynamic tag #{tag} (value #{'0x%08X' % val})" if $VERBOSE
				else
					@tag[tag] = val
				end
			end
		end
	end

	# interprets tags (convert flags, arrays etc), mark them as self.encoded.export
	def decode_segments_tags_interpret
		if @tag['STRTAB']
			if not sz = @tag['STRSZ']
				puts "W: Elf: no string table size tag" if $VERBOSE
			else
				if l = add_label('dynamic_strtab', @tag['STRTAB'])
					@tag['STRTAB'] = l
					strtab = @encoded[l, sz].data
				end
			end
		end

		@tag.keys.each { |k|
			case k
			when Integer
			when 'NEEDED'
				# array of strings
				if not strtab
					puts "W: Elf: no string table, needed for tag #{k}" if $VERBOSE
					next
				end
				@tag[k].map! { |v| readstr(strtab, v) }
			when 'SONAME', 'RPATH', 'RUNPATH'
				# string
				if not strtab
					puts "W: Elf: no string table, needed for tag #{k}" if $VERBOSE
					next
				end
				@tag[k] = readstr(strtab, @tag[k])
			when 'INIT', 'FINI', 'PLTGOT', 'HASH', 'GNU_HASH', 'SYMTAB', 'RELA', 'REL', 'JMPREL'
				@tag[k] = add_label('dynamic_' + k.downcase, @tag[k]) || @tag[k]
			when 'INIT_ARRAY', 'FINI_ARRAY', 'PREINIT_ARRAY'
				next if not l = add_label('dynamic_' + k.downcase, @tag[k])
				if not sz = @tag.delete(k+'SZ')
					puts "W: Elf: tag #{k} has no corresponding size tag" if $VERBOSE
					next
				end

				tab = @encoded[l, sz]
				tab.ptr = 0
				@tag[k] = []
				while tab.ptr < tab.length
					a = decode_addr(tab)
					@tag[k] << (add_label("dynamic_#{k.downcase}_#{@tag[k].length}", a) || a)
				end
			when 'PLTREL';     @tag[k] =  int_to_hash(@tag[k], DYNAMIC_TAG)
			when 'FLAGS';      @tag[k] = bits_to_hash(@tag[k], DYNAMIC_FLAGS)
			when 'FLAGS_1';    @tag[k] = bits_to_hash(@tag[k], DYNAMIC_FLAGS_1)
			when 'FEATURES_1'; @tag[k] = bits_to_hash(@tag[k], DYNAMIC_FEATURES_1)
			end
		}
	end

	# read symbol table, and mark all symbols found as exports of self.encoded
	# tables locations are found in self.tags
	# XXX symbol count is found from the hash table, this may not work with GNU_HASH only binaries
	def decode_segments_symbols
		return unless @tag['STRTAB'] and @tag['STRSZ'] and @tag['SYMTAB'] and (@tag['HASH'] or @tag['GNU_HASH'])
			
		raise "E: ELF: unsupported symbol entry size: #{@tag['SYMENT']}" if @tag['SYMENT'] != Symbol.size(self)
		
		# find number of symbols
		if @tag['HASH']
			@encoded.ptr = @tag['HASH']	# assume tag already interpreted (would need addr_to_off otherwise)
			decode_word
			sym_count = decode_word
		else
			raise 'metasm internal error: TODO find sym_count from gnu_hash'
			@encoded.ptr = @tag['GNU_HASH']
			decode_word
			sym_count = decode_word	# non hashed symbols
			# XXX UNDEF symbols are not hashed
		end
			
		strtab = @encoded[@tag['STRTAB'], @tag['STRSZ']].data

		@encoded.ptr = @tag['SYMTAB']
		@symbols.clear
		sym_count.times {
			s = Symbol.new
			s.decode self, strtab
			@symbols << s

			# mark in @encoded.export
			if s.name and s.shndx != 'UNDEF' and %w[NOTYPE OBJECT FUNC].include?(s.type)
				if not o = addr_to_off(s.value)
					# allow to point to end of segment
					if not seg = @segments.find { |seg| seg.type == 'LOAD' and seg.vaddr + seg.memsz == s.value }	# check end
						puts "W: Elf: symbol points to unmmaped space (#{s.inspect})" if $VERBOSE and s.shndx != 'ABS'
						next
					end
					# LoadedELF would have returned an addr_to_off = addr
					o = s.value - seg.vaddr + seg.offset
				end
				name = s.name
				while @encoded.export[name] and @encoded.export[name] != o
					puts "W: Elf: symbol #{name} already seen at #{'%X' % @encoded.export[name]} - now at #{'%X' % o}) (may be a different version definition)" if $VERBOSE
					name += '_'	# do not modify inplace
				end
				@encoded.add_export name, o
			end
		}

		check_symbols_hash if $VERBOSE
		check_symbols_gnu_hash if $VERBOSE
	end

	# decode relocation tables (REL, RELA, JMPREL) from @tags
	def decode_segments_relocs
		@relocations.clear
		if @encoded.ptr = @tag['REL']
			raise "E: ELF: unsupported rel entry size #{@tag['RELENT']}" if @tag['RELENT'] != Relocation.size(self)
			p_end = @encoded.ptr + @tag['RELSZ']
			while @encoded.ptr < p_end
				r = Relocation.new
				r.decode self, @symbols
				@relocations << r
			end
		end

		if @encoded.ptr = @tag['RELA']
			raise "E: ELF: unsupported rela entry size #{@tag['RELAENT'].inspect}" if @tag['RELAENT'] != Relocation.size_a(self)
			p_end = @encoded.ptr + @tag['RELASZ']
			while @encoded.ptr < p_end
				r = Relocation.new
				r.decode_addend self, @symbols
				@relocations << r
			end
		end

		if @encoded.ptr = @tag['JMPREL']
			case reltype = @tag['PLTREL']
			when 'REL';  msg = :decode
			when 'RELA'; msg = :decode_addend
			else raise "E: ELF: unsupported plt relocation type #{reltype}"
			end
			p_end = @encoded.ptr + @tag['PLTRELSZ']
			while @encoded.ptr < p_end
				r = Relocation.new
				r.send(msg, self, @symbols)
				@relocations << r
			end
		end
	end

	# use relocations as self.encoded.reloc
	def decode_segments_relocs_interpret
		relocproc = "arch_decode_segments_reloc_#{@header.machine.to_s.downcase}"
		if not respond_to? relocproc
			puts "W: Elf: relocs for arch #{@header.machine} unsupported" if $VERBOSE
			@relocations.each { |r| puts Expression[r.offset] }
			return
		end
		@relocations.each { |r|
			next if r.offset == 0
			if not o = addr_to_off(r.offset)
				puts "W: Elf: relocation in unmmaped space (#{r.inspect})" if $VERBOSE
				next
			end
			if @encoded.reloc[o]
				puts "W: Elf: not rerelocating address #{'%08X' % r.offset}" if $VERBOSE
				next
			end
			@encoded.ptr = o
			if rel = send(relocproc, r)
				@encoded.reloc[o] = rel
			end
		}
	end

	# returns the Metasm::Relocation that should be applied for reloc
	# self.encoded.ptr must point to the location that will be relocated (for implicit addends)
	def arch_decode_segments_reloc_386(reloc)
		if reloc.symbol and n = reloc.symbol.name and reloc.symbol.shndx == 'UNDEF' and @sections and
			s = @sections.find { |s| s.name and s.offset <= @encoded.ptr and s.offset + s.size > @encoded.ptr }
			@encoded.add_export(new_label("#{s.name}_#{n}"), @encoded.ptr, true)
		end

		# decode addend if needed
		case reloc.type
		when 'NONE', 'COPY', 'GLOB_DAT', 'JMP_SLOT' # no addend
		else addend = reloc.addend || decode_sword
		end

		case reloc.type
		when 'NONE'
		when 'RELATIVE'
			# base = @segments.find_all { |s| s.type == 'LOAD' }.map { |s| s.vaddr }.min & 0xffff_f000
			# compiled to be loaded at seg.vaddr
			target = addend
			if o = addr_to_off(target)
				if not label = @encoded.inv_export[o]
					label = new_label('xref_%04x' % target)
					@encoded.add_export label, o
				end
				target = label
			else
				puts "W: Elf: relocation pointing out of mmaped space #{reloc.inspect}" if $VERBOSE
			end
		when 'GLOB_DAT', 'JMP_SLOT', '32', 'PC32', 'TLS_TPOFF', 'TLS_TPOFF32'
			# XXX use versionned version
			# lazy jmp_slot ?
			target = 0
			target = reloc.symbol.name if reloc.symbol.kind_of?(Symbol) and reloc.symbol.name
			target = Expression[target, :-, reloc.offset] if reloc.type == 'PC32'
			target = Expression[target, :+, addend] if addend and addend != 0
			target = Expression[target, :+, 'tlsoffset'] if reloc.type == 'TLS_TPOFF'
			target = Expression[:-, [target, :+, 'tlsoffset']] if reloc.type == 'TLS_TPOFF32'
		when 'COPY'
			# mark the address pointed as a copy of the relocation target
			if not reloc.symbol or not name = reloc.symbol.name
				puts "W: Elf: symbol to COPY has no name: #{reloc.inspect}" if $VERBOSE
				name = ''
			end
			name = new_label("copy_of_#{name}")
			@encoded.add_export name, @encoded.ptr
			target = nil
		else
			puts "W: Elf: unhandled 386 reloc #{reloc.inspect}" if $VERBOSE
			target = nil
		end

		Metasm::Relocation.new(Expression[target], :u32, @endianness) if target
	end

	# returns the Metasm::Relocation that should be applied for reloc
	# self.encoded.ptr must point to the location that will be relocated (for implicit addends)
	def arch_decode_segments_reloc_mips(reloc)
		if reloc.symbol and n = reloc.symbol.name and reloc.symbol.shndx == 'UNDEF' and @sections and
			s = @sections.find { |s| s.name and s.offset <= @encoded.ptr and s.offset + s.size > @encoded.ptr }
			@encoded.add_export(new_label("#{s.name}_#{n}"), @encoded.ptr, true)
		end

		# decode addend if needed
		case reloc.type
		when 'NONE' # no addend
		else addend = reloc.addend || decode_sword
		end

		case reloc.type
		when 'NONE'
		when '32', 'REL32'
			target = 0
			target = reloc.symbol.name if reloc.symbol.kind_of?(Symbol) and reloc.symbol.name
			target = Expression[target, :-, reloc.offset] if reloc.type == 'REL32'
			target = Expression[target, :+, addend] if addend and addend != 0
		else
			puts "W: Elf: unhandled MIPS reloc #{reloc.inspect}" if $VERBOSE
			target = nil
		end

		Metasm::Relocation.new(Expression[target], :u32, @endianness) if target
	end

	# decodes the ELF dynamic tags, interpret them, and decodes symbols and relocs
	def decode_segments_dynamic
		return if not dynamic = @segments.find { |s| s.type == 'DYNAMIC' }
		@encoded.ptr = add_label('dynamic_tags', dynamic.vaddr)
		decode_tags
		decode_segments_tags_interpret
		decode_segments_symbols
		decode_segments_relocs
		decode_segments_relocs_interpret
	end

	# decodes the dynamic segment, fills segments.encoded
	def decode_segments
		decode_segments_dynamic
		@segments.each { |s|
			case s.type
			when 'LOAD', 'INTERP'
				s.encoded = @encoded[s.offset, s.filesz]
				s.encoded.virtsize = s.memsz if s.memsz > s.encoded.virtsize
			end
		}
	end

	# decodes sections, interprets symbols/relocs, fills sections.encoded
	def decode_sections
		@sections.each { |s|
			case s.type
			when 'PROGBITS', 'NOBITS'
			when 'TODO'	# TODO
			end
		}
		@sections.find_all { |s| s.type == 'PROGBITS' or s.type == 'NOBITS' }.each { |s|
			if s.flags.include? 'ALLOC'
				if s.type == 'NOBITS'
					s.encoded = EncodedData.new :virtsize => s.size
				else
					s.encoded = @encoded[s.offset, s.size] || EncodedData.new
					s.encoded.virtsize = s.size
				end
			end
		}
	end

	# decodes the elf header, and depending on the elf type, decode segments or sections
	def decode
		decode_header
		case @header.type
		when 'DYN', 'EXEC'; decode_segments
		when 'REL'; decode_sections
		when 'CORE'
		end
	end

	def each_section
		@segments.each { |s| yield s.encoded, s.vaddr if s.type == 'LOAD' }
		# @sections ?
	end

	# returns a metasm CPU object corresponding to +header.machine+
	def cpu_from_headers
		case @header.machine
		when '386'; Ia32.new
		when 'MIPS'; MIPS.new @endianness
		else raise "unknown cpu #{@header.machine}"
		end
	end

	# returns an array including the ELF entrypoint (if not null) and the FUNC symbols addresses
	# TODO include init/init_array
	def get_default_entrypoints
		ep = []
		ep << @header.entry if @header.entry != 0
		@symbols.each { |s|
			ep << s.value if s.shndx != 'UNDEF' and s.type == 'FUNC'
		} if @symbols
		ep
	end

	def dump_section_header(addr, edata)
		if s = @segments.find { |s| s.vaddr == addr }
			"\n// ELF segment at #{Expression[addr]}, flags = #{s.flags.sort.join(', ')}"
		else super
		end
	end

	# returns a disassembler with a special decodedfunction for dlsym, __libc_start_main, and a default function (i386 only)
	def init_disassembler
		d = super
		d.backtrace_maxblocks_data = 4
		case @cpu
		when Ia32
			old_cp = d.c_parser
			d.c_parser = nil
			d.parse_c 'void *dlsym(int, char *);'
			d.parse_c 'void __libc_start_main(void(*)(), int, int, void(*)(), void(*)()) __attribute__((noreturn));'
			dls  = @cpu.decode_c_function_prototype(d.c_parser, 'dlsym')
			main = @cpu.decode_c_function_prototype(d.c_parser, '__libc_start_main')
			d.c_parser = old_cp
			dls.btbind_callback = proc { |dasm, bind, funcaddr, calladdr, expr, origin, maxdepth|
				sz = @cpu.size/8
				raise 'dlsym call error' if not dasm.decoded[calladdr]
				fnaddr = dasm.backtrace(Indirection.new(Expression[:esp, :+, 2*sz], sz, calladdr), calladdr, :include_start => true, :maxdepth => maxdepth)
				if fnaddr.kind_of? ::Array and fnaddr.length == 1 and s = dasm.get_section_at(fnaddr.first) and fn = s[0].read(64) and i = fn.index(0) and i > sz	# try to avoid ordinals
					bind = bind.merge :eax => Expression[fn[0, i]]
				end
				bind
			}
			d.function[Expression['dlsym']] = dls
			d.function[Expression['__libc_start_main']] = main
			df = d.function[:default] = @cpu.disassembler_default_func
			df.backtrace_binding[:esp] = Expression[:esp, :+, 4]
			df.btbind_callback = nil
		when MIPS
			(d.address_binding[@header.entry] ||= {})[:$t9] ||= Expression[@header.entry]
			@symbols.each { |s|
				next if s.shndx == 'UNDEF' or s.type != 'FUNC'
				(d.address_binding[s.value] ||= {})[:$t9] ||= Expression[s.value]
			}
			d.function[:default] = @cpu.disassembler_default_func
		end
		d
	end
end

class LoadedELF < ELF
	attr_accessor :load_address
	def addr_to_off(addr)
		@load_address ||= 0
		addr >= @load_address ? addr - @load_address : addr if addr
	end

	# decodes the dynamic segment, fills segments.encoded
	def decode_segments
		decode_segments_dynamic
		@segments.each { |s|
			if s.type == 'LOAD'
				s.encoded = @encoded[s.vaddr, s.memsz]
			end
		}
	end

	# do not try to decode the section header by default
	def decode_header(off = 0)
		@encoded.ptr = off
		@header.decode self
		decode_program_header(@header.phoff+off)
	end
end
end