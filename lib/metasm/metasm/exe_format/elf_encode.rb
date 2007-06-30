#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/encode'
require 'metasm/exe_format/elf'

module Metasm
class ELF
	class Header
		def encode elf, ph, sh
			set_default_values elf, ph, sh

			h = EncodedData.new <<
			"\x7fELF" <<
			case @e_class
			when 32: 1
			when 64: 2
			else raise "E: Elf: unsupported class #@e_class"
			end <<
			case @endianness
			when :little: 1
			when :big: 2
			else raise "E: Elf: unsupported endianness #@endianness"
			end <<
			1 <<
			elf.int_from_hash(@abi, ABI) <<
			@abi_version

			h.align 16

			h <<
			elf.encode_half(elf.int_from_hash(@type, TYPE)) <<
			elf.encode_half(elf.int_from_hash(@machine, MACHINE)) <<
			elf.encode_word(elf.int_from_hash(@version, VERSION)) <<
			elf.encode_addr(@entry) <<
			elf.encode_off( @phoff) <<
			elf.encode_off( @shoff) <<
			elf.encode_word(elf.bits_from_hash(@flags, FLAGS[@machine])) <<
			elf.encode_half(@ehsize) <<
			elf.encode_half(@phentsize) <<
			elf.encode_half(@phnum) <<
			elf.encode_half(@shentsize) <<
			elf.encode_half(@shnum) <<
			elf.encode_half(@shstrndx)
		end

		def set_default_values elf, h, ph, sh
		#	@e_class   ||= elf.cpu.size			# those are heavily used by all other encode, and must be set long before we get here
		#	@endianness||= elf.cpu.endianness
			@type      ||= 'EXEC'
			@machine   ||= '386'	# TODO			# should probably be set at the same time as class/endianness
			@version   ||= 1
			@abi       ||= 0
			@abi_version ||= 0
			@entry     ||= 'entrypoint'
			@phoff     ||= ph ? Expression[elf.label_at(ph, 0), :-, elf.label_at(elf.encoded, 0)] : 0
			@shoff     ||= sh ? Expression[elf.label_at(ph, 0), :-, elf.label_at(elf.encoded, 0)] : 0
			@flags     ||= 0
			@ehsize    ||= 52
			@phentsize ||= @e_class == 32 ? 32 : 56
			@phnum     ||= elf.segments.to_a.length
			@shentsize ||= @e_class == 32 ? 40 : 64
			@shnum     ||= elf.sections.to_a.length
			@shstrndx  ||= 0

		end
	end

	class Section
		# needs elf.encoded (for offset)
		def encode elf
			set_default_values elf

			elf.encode_word( @name_p) <<
			elf.encode_word(elf.int_from_hash(@type, SH_TYPE)) <<
			elf.encode_xword(elf.bits_from_hash(@flags, SH_FLAGS)) <<
			elf.encode_addr( @addr) <<
			elf.encode_off(  @offset) <<
			elf.encode_xword(@size) <<
			elf.encode_word( @link.kind_of?(Section) ? elf.sections.index(@link) : @link) <<
			elf.encode_word( @info.kind_of?(Section) ? elf.sections.index(@info) : @info) <<
			elf.encode_xword(@addralign) <<
			elf.encode_xword(@entsize)
		end

		def set_default_values elf
			@name_p ||= default_make_name_p elf	# must occur before @size default initialization
			@type   ||= 0
			@flags  ||= 0
			@addr   ||= @encoded ? elf.label_at(@encoded, 0) : 0
			@offset ||= 0
			@size   ||= @encoded ? @encoded.virtsize : 0
			@link   ||= 0
			@info   ||= 0
			@addralign ||= @entsize || 0
			@entsize ||= @addralign
		end

		# returns the @name_p field, after adding @name to .shstrndx (creating it if needed)
		def default_make_name_p elf
			return 0 if not @name or @name.empty?
			if elf.header.shstrndx.to_i == 0
				sn = new
				sn.name = '.shstrndx'
				sn.type = 'STRTAB'
				sn.addralign = 1
				sn.encoded = EncodedData << 0
				elf.header.shstrndx = elf.sections.length
				elf.sections << sn
			end
			sn = elf.sections[elf.header.shstrndx]
			ptr = sn.encoded.virtsize
			sn.encoded << @name << 0
			ptr
		end
	end

	class Segment
		def encode elf
			set_default_values elf

			elf.encode_word(elf.int_from_hash(@type, PH_TYPE)) <<
			(elf.encode_word(elf.bits_from_hash(@flags, PH_FLAGS)) if elf.header.e_class == 64) <<
			elf.encode_off( @offset) <<
			elf.encode_addr(@vaddr) <<
			elf.encode_addr(@paddr) <<
			elf.encode_xword(@filesz) <<
			elf.encode_xword(@memsz) <<
			(elf.encode_word(elf.bits_from_hash(@flags, PH_FLAGS)) if elf.header.e_class == 32) <<
			elf.encode_xword(@align)
		end

		def set_default_values elf
			@type   ||= 0
			@flags  ||= 0
			@offset ||= 0
			@vaddr  ||= @encoded ? elf.label_at(@encoded, 0) : 0
			@paddr  ||= @vaddr
			@filesz ||= @encoded ? @encoded.rawsize : 0
			@memsz  ||= @encoded ? @encoded.virtsize : 0
			@align  ||= 0
		end
	end

	class Symbol
		def encode(elf, strtab=nil)
			set_default_values elf, strtab

			case elf.e_class
			when 32
				elf.encode_word(@name_p) <<
				elf.encode_addr(@value) <<
				elf.encode_word(@size) <<
				elf.encode_uchar(@info) <<
				elf.encode_uchar(@other) <<
				elf.encode_half(elf.int_from_hash(@shndx, SH_INDEX))
			when 64
				elf.encode_word(@name_p) <<
				elf.encode_uchar(@info) <<
				elf.encode_uchar(@other) <<
				elf.encode_half(elf.int_from_hash(@shndx, SH_INDEX)) <<
				elf.encode_addr(@value) <<
				elf.encode_xword(@size)
			end
		end

		def set_default_values(elf, strtab)
			@name_p ||= default_make_name_p elf, strtab
			@value  ||= 0
			@size   ||= 0
			@bind  ||= 0
			@type  ||= 0
			@info   ||= ((elf.int_from_hash(@bind, SYMBOL_BIND) & 15) << 4) | (elf.int_from_hash(@type, SYMBOL_TYPE) & 15)
			@other  ||= 0
			@shndx = elf.sections.index(@shndx) if @shndx.kind_of? Section
			@shndx  ||= 0
		end

		# returns the value of @name_p, after adding @name to the symbol string table
		def default_make_name_p(elf, strtab)
			ret = 0
			if @name and not @name.empty?
				raise 'E: Elf: need string table to store symbol names' if not strtab
				if not ret = strtab.data.index(@name + 0.chr)
					ret = strtab.virtsize
					strtab << @name << 0
				end
			end
			ret
		end
	end

	class Relocation
		def encode(elf, ary=nil)
			set_default_values elf, ary

			elf.encode_addr(r, @offset) <<
			elf.encode_xword(r, @info) <<
			(elf.encode_sxword(r, @addend) if @addend)
		end

		def set_default_values(elf, ary)
			@offset ||= 0
			@symbol ||= 0
			@type  ||= 0
			@info   ||= default_make_info elf, ary
		end

		# returns the numeric value of @info from @type and @symbol
		def default_make_info(elf, ary)
			type = elf.int_from_hash(@type, RELOCATION_TYPE.fetch(elf.header.machine, {}))
			symb = @symbol.kind_of?(Symbol) ? ary.index(@symbol) : @symbol
			case elf.header.e_class
			when 32: (type & 0xff) | ((symb & 0xff_ffff) << 8)
			when 64: (type & 0xffff_ffff) | ((symb & 0xffff_ffff) << 32)
			end
		end
	end


	def encode_uchar(w)  Expression[w].encode(:u8, @header.endianness) end
	def encode_half(w)   Expression[w].encode(:u16, @header.endianness) end
	def encode_word(w)   Expression[w].encode(:u32, @header.endianness) end
	def encode_sword(w)  Expression[w].encode(:i32, @header.endianness) end
	def encode_xword(w)  Expression[w].encode((@header.e_class == 32 ? :u32 : :u64), @header.endianness) end
	def encode_sxword(w) Expression[w].encode((@header.e_class == 32 ? :i32 : :i64), @header.endianness) end
	alias encode_addr encode_xword
	alias encode_off  encode_xword

	def encode_check_section_size(s)
		if s.size and s.encoded.virtsize < s
			puts "W: Elf: preexisting section #{s} has grown, relocating"
			s.addr = s.offset = nil
			s.size = s.encoded.virtsize
		end
	end

	def encode_reorder_symbols
		gnu_hash_bucket_length = 42	# TODO
		@symbols[1..-1] = @symbols[1..-1].sort_by { |s|
			if s.binding != 'GLOBAL'
				-2
			elsif s.shndx == 'UNDEF' or not s.name
				-1
			else
				ELF.gnu_hash_symbol_name(s.name) % gnu_hash_bucket_length
			end
		}
	end

	def encode_insert_sorted_section s
		# order: r rx rw noalloc
		rank = proc { |sec| sec.flags.include?('ALLOC') ? !sec.flags.include?('WRITE') ? !sec.flags.include?('EXECINSTR') ? 0 : 1 : 2 : 3 }
		srank = rank[s]
		nexts = @sections.find { |sec| rank[sec] > srank }	# find section with rank superior
		nexts = nexts ? @sections.index(nexts) : -1		# if none, last
		@sections.insert(nexts, s)				# insert section
	end

	def encode_gnu_hash
		return
		# TODO

		return if not @symbols

		sortedsyms = @symbols.find_all { |s| s.binding == 'GLOBAL' and s.shndx != 'UNDEF' and s.name }
		bucket = Array.new(42)

		if not gnu_hash = @sections.find { |s| s.type == 'GNU_HASH' }
			gnu_hash = Section.new
			gnu_hash.name = '.gnu.hash'
			gnu_hash.type = 'GNU_HASH'
			gnu_hash.flags = ['ALLOC']
			gnu_hash.entsize = gnu_hash.addralign = 4
			encode_insert_sorted_section gnu_hash
		end
		gnu_hash.encoded = EncodedData.new

		# "bloomfilter[N] has bit B cleared if there is no M (M > symndx) which satisfies (C = @header.class)
		# ((gnu_hash(sym[M].name) / C) % maskwords) == N	&&
		# ((gnu_hash(sym[M].name) % C) == B			||
		# ((gnu_hash(sym[M].name) >> shift2) % C) == B"
		# bloomfilter may be [~0]
		bloomfilter = []
		
		# bucket[N] contains the lowest M for which
		# gnu_hash(sym[M]) % nbuckets == N
		# or 0 if none
		bucket = []

		gnu_hash.encoded <<
		encode_word(bucket.length) <<
		encode_word(@symbols.length - sortedsyms.length) <<
		encode_word(bloomfilter.length) <<
		encode_word(shift2)
		bloomfilter.each { |bf| gnu_hash.encoded << encode_xword(bf) }
		bucket.each { |bk| gnu_hash.encoded << encode_word(bk) }
		sortedsyms.each { |s|
			# (gnu_hash(sym[N].name) & ~1) | (N == dynsymcount-1 || (gnu_hash(sym[N].name) % nbucket) != (gnu_hash(sym[N+1].name) % nbucket))
			# that's the hash, with its lower bit replaced by the bool [1 if i am the last sym having my hash as hash]
			val = 28
			gnu_hash.encoded << encode_word(val)
		}

		@tag['GNU_HASH'] = label_at(gnu_hash.encoded, 0)

		encode_check_section_size gnu_hash

		gnu_hash
	end

	def encode_hash
		return if not @symbols

		if not hash = @sections.find { |s| s.type == 'HASH' }
			hash = Section.new
			hash.name = '.hash'
			hash.type = 'HASH'
			hash.flags = ['ALLOC']
			hash.entsize = hash.addralign = 4
			encode_insert_sorted_section hash
		end
		hash.encoded = EncodedData.new
		
		# to find a symbol from its name :
		# 1: idx = hash(name)
		# 2: idx = bucket[idx % bucket.size]
		# 3: if idx == 0: return notfound
		# 4: if dynsym[idx].name == name: return found
		# 5: idx = chain[idx] ; goto 3
		bucket = Array.new(@symbols.length/4+1, 0)
		chain =  Array.new(@symbols.length, 0)
		@symbols.each_with_index { |s, i|
			next if s.binding != GLOBAL or not s.name or s.shndx == 'UNDEF'
			hash = ELF.hash_symbol_name(s.name)
			hash_mod = hash % bucket.length
			chain[i] = bucket[hash_mod]
			bucket[hash_mod] = i
		}

		hash.encoded << encode_word(bucket.length) << encode_word(chain.length)

		bucket.each { |b| hash.encoded << encode_word(b) }
		chain.each { |c| hash.encoded << encode_word(c) }

		@tag['HASH'] = label_at(hash.encoded, 0)

		encode_check_section_size hash

		hash
	end

	def encode_segments_symbols(strtab)
		return if not @symbols

		if not dynsym = @sections.find { |s| s.type == 'DYNSYM' }
			dynsym = Section.new
			dynsym.name = '.dynsym'
			dynsym.type = 'DYNSYM'
			dynsym.entsize = dynsym.addralign = Symbol.size(self)
			dynsym.flags = ['ALLOC']
			dynsym.info = @symbols.find_all { |s| s.binding == 'LOCAL' }.length
			dynsym.link = strtab
			encode_insert_sorted_section dynsym
		end
		dynsym.encoded = EncodedData.new
		@symbols.each { |s| dynsym.encoded << s.encode(self, strtab.encoded) }	# needs all section indexes, as will be in the final section header

		@tag['SYMTAB'] = label_at(dynsym.encoded, 0)
		@tag['SYMENT'] = Symbol.size(self)

		encode_check_section_size dynsym

		dynsym
	end

	def encode_segments_relocs
		return if not @relocations

		list = @relocations.find_all { |r| r.type == 'JMP_SLOT' }
		if list.any?
			list.each { |r| r.addend ||= 0 } if list.find { |r| r.addend }
			if not relplt = @sections.find { |s| s.type == 'REL' and s.name == '.rel.plt' } 	# XXX arch-dependant ?
				relplt = Section.new
				relplt.name = '.rel.plt'
				relplt.flags = ['ALLOC']
				encode_insert_sorted_section relplt
			end
			relplt.encoded = EncodedData.new
			list.each { |r| relplt.encoded << r.encode(self, @symbols) }
			@tag['JMPREL'] = label_at(relplt.encoded, 0)
			@tag['PLTRELSZ'] = relplt.encoded.virtsize
			if list.first.addend
				@tag['PLTREL'] = relplt.type = 'RELA'
				@tag['RELAENT'] = relplt.entsize = relplt.addralign = Relocation.size_a(self)
			else
				@tag['PLTREL'] = relplt.type = 'REL'
				@tag['RELENT'] = relplt.entsize = relplt.addralign = Relocation.size(self)
			end
			encode_check_segment_size relplt
		end

		list = @relocations.find_all { |r| r.type != 'JMP_SLOT' and not r.addend }
		if list.any?
			if not rel = @sections.find { |s| s.type == 'REL' and s.name == '.rel.dyn' }
				rel = Section.new
				rel.name = '.rel.dyn'
				rel.type = 'REL'
				rel.flags = ['ALLOC']
				rel.entsize = rel.addralign = Relocation.size(self)
				encode_insert_sorted_section rel
			end
			rel.encoded = EncodedData.new
			list.each { |r| rel.encoded << r.encode(self, @symbols) }
			@tag['REL'] = label_at(rel.encoded, 0)
			@tag['RELENT'] = Relocation.size(self)
			@tag['RELSZ'] = rel.encoded.virtsize
			encode_check_section_size rel
		end

		list = @relocations.find_all { |r| r.type != 'JMP_SLOT' and r.addend }
		if list.any?
			if not rela = @sections.find { |s| s.type == 'RELA' and s.name == '.rela.dyn' }
				rela = Section.new
				rela.name = '.rela.dyn'
				rela.type = 'RELA'
				rela.flags = ['ALLOC']
				rela.entsize = rela.addralign = Relocation.size_a(self)
				encode_insert_sorted_section rela
			end
			rela.encoded = EncodedData.new
			list.each { |r| rela.encoded << r.encode(self, @symbols) }
			@tag['RELA'] = label_at(rela.encoded, 0)
			@tag['RELAENT'] = Relocation.size(self)
			@tag['RELASZ'] = rela.encoded.virtsize
			encode_check_section_size rela
		end
	end

	# encodes the .dynamic section, creates .hash/.gnu.hash/.rel/.rela/.dynsym/.strtab/.init,*_array as needed
	def encode_segments_tags
		if not strtab = @sections.find { |s| s.type == 'STRTAB' and s.flags.include? 'ALLOC' }
			strtab = Section.new
			strtab.name = '.dynstr'
			strtab.align = 1
			strtab.type = 'STRTAB'
			strtab.flags = ['ALLOC']
			strtab.encoded = EncodedData.new << 0
			strtab.flags 
			encode_insert_sorted_section strtab
		end
		@tag['STRTAB'] = label_at(strtab.encoded, 0)

		if not dynamic = @sections.find { |s| s.type == 'DYNAMIC' }
			dynamic = Section.new
			dynamic.name = '.dynamic'
			dynamic.type = 'DYNAMIC'
			dynamic.flags = %w[WRITE ALLOC]		# XXX why write ?
			dynamic.addralign = dynamic.entsize = @header.e_class / 8 * 2
			dynamic.link = strtab
			encode_insert_sorted_section dynamic
		end
		dynamic.encoded = EncodedData.new
		encode_tag = proc { |k, v| dynamic.encoded << encode_sxword(int_from_hash(k, DYNAMIC_TAG)) << encode_xword(v) }

		# create strings
		add_str = proc { |n|
			if n and not n.empty? and not ret = strtab.encoded.data.index(n + 0.chr)
				ret = strtab.encoded.virtsize
				strtab.encoded << n << 0
			end
			ret || 0
		}
		@tag.keys.each { |k|
			case k
			when 'NEEDED': @tag[k].each { |n| encode_tag[k, add_str[n]] }
			when 'SONAME', 'RPATH', 'RUNPATH': encode_tag[k, add_str[@tag[k]]]
			when 'INIT_ARRAY', 'FINI_ARRAY', 'PREINIT_ARRAY'	# build section containing the array
				if not ar = @sections.find { |s| s.name == '.' + k.downcase }
					ar = Section.new
					ar.name = '.' + k.downcase
					ar.type = 'PROGBITS'
					ar.addralign = ar.entsize = @header.e_class/8
					ar.flags = %w[WRITE ALLOC]	# why write ? base reloc ?
					encode_insert_sorted_section ar # insert before encoding syms/relocs (which need section indexes)
				end
			end
		}

		encode_reorder_symbols
		encode_gnu_hash
		encode_hash
		encode_segments_relocs
		dynsym = encode_segments_symbols(strtab)
		@sections.find_all { |s| %w[HASH GNU_HASH REL RELA].include? type }.each { |s| s.link = dynsym }

		encode_check_section_size strtab

		# XXX any order needed ?
		@tag.keys.each { |k|
			case k
			when Integer	# unknown tags = array of values
				@tag[k].each { |n| encode_tag[k, n] }
			when 'PLTREL':     encode_tag[k,  int_from_hash(@tag[k], DYNAMIC_TAG)]
			when 'FLAGS':      encode_tag[k, bits_from_hash(@tag[k], DYNAMIC_FLAGS)]
			when 'FLAGS_1':    encode_tag[k, bits_from_hash(@tag[k], DYNAMIC_FLAGS_1)]
			when 'FEATURES_1': encode_tag[k, bits_from_hash(@tag[k], DYNAMIC_FEATURES_1)]
			when 'NULL'	# keep last
			when 'STRTAB'
				encode_tag[k, @tag[k]]
				encode_tag['STRSZ', strtab.size]
			when 'INIT_ARRAY', 'FINI_ARRAY', 'PREINIT_ARRAY'	# build section containing the array
				ar = @sections.find { |s| s.name == '.' + k.downcase }
				ar.encoded = EncodedData.new
				@tag[k].each { |p| ar.encoded << encode_addr(p) }
				encode_check_section_size ar
				encode_tag[k, label_at(ar.encoded, 0)]
				encode_tag[k + 'SZ', ar.encoded.virtsize]
			else 
				encode_tag[k, @tag[k]]
			end
		}
		encode_tag['NULL', @tag['NULL'] || 0]

		encode_check_section_size dynamic
	end

	def encode_segments(opts)
		# only segment with data not in a section: PHDR (first)
		vaddr = 0x08048000
		@sections.each { |s|
			next if not s.alloc
		}
		@segments.each { |s|
			case s.type
			when 'LOAD': s.offset = new_label ; s.virtaddr = new_label
			when 'PHDR': s.offset = new_label ; s.filesize = s.memsize = new_label
			end
		}

		phdr = EncodedData.new
		@segments.each { |s| phdr << s.encode(self) }
		phdr
	end

	def assemble(source)
		@sections ||= [Section.new]

		source.each { |name, ary|
			@sections.find{ |s| s.name == name }.encoded = assemble_section ary	# this is old Section.encode
		}

		if not opts.delete 'no_phdr_segment'
			phdr = Segment.new
			phdr.type = 'PHDR'
			phdr.addralign = @header.e_class/8
			phdr.offset = new_label
			phdr.vaddr  = new_label
			phdr.filesz = phdr.memsz = new_label
			@segments << phdr
		else
			# TODO
		end

		if interp = opts.delete('interp')
			i = Section.new
			i.name = '.interp'
			i.type = 'PROGBITS'
			i.encoded = EncodedData.new << interp << 0
			i.align = 1
			i.addr = label_at i.encoded, 0
			i.offset = new_label
			i.size = i.encoded.virtsize
			@sections << i
			ii = Segment.new
			ii.type = 'INTERP'
			ii.addralign = 1
			ii.offset = i.offset
			ii.vaddr = i.addr
			ii.filesz = ii.memsz = i.size
			@segments << ii
		end

		encode_segments_tag

		encode_segments
	end
end
end

__END__
elf.parse <<EOE
.text				; @sections << Section.new('.text', ['r' 'x'])
.global ".foo", foo		; @symbols ||= [0] << Symbol.new(global, '.foo', addr=foo)
.global bar			; @symbols << Symbol.new(global, 'bar', undef)
.need 'libc.so.6'		; @tag['NEEDED'] ||= [] << 'libc.so.6'
.soname 'lolol'			; @tag['SONAME'] = 'lolol'
jmp kikoo
kikoo: ret
foo: testic
.func blabla			; @symbols << [local, 'blabla', func] ; src << Label('blabla')
x x x
.endfunc blabla			; @symbols.find('blabla').size = Expr[$, :-, 'blabla']

.plt 'baz'	; @section['.plt'] ||= encode('pltstart: push _got; jmp dlresolv') << encode('baz: jmp [pltgot+#{pltgot.virtsize}] ; baz_pltsetup: push #{@tag['PLTREL'].length} ; jmp pltstart')
		; @relocs << Reloc(Sym('baz', func, global, undef), jmp_slot, target=pltgot+pltgot.virtsize)
		; @tag['pltgot'] << encode('dd baz_pltsetup')
		; XXX ET_REL ?
call baz
EOE

__END__
		program.sections.each { |sect|
			s.type = s.edata.data.empty? ? 'NOBITS' : 'PROGBITS'
			s.flags << 'WRITE' if sect.mprot.include? :write
			s.flags << 'EXECINSTR' if sect.mprot.include? :exec
		}

		encode[pltgot, :u32, program.label_at(dynamic.edata, 0)]	# reserved, points to _DYNAMIC
		#if arch == '386'
			encode[pltgot, :u32, 0]	# ptr to dlresolve
			encode[pltgot, :u32, 0]	# ptr to got?
		#end
		end

		if pltgot
		# XXX the plt entries need not to follow this model
		# XXX arch-specific, parser-dependant...
		program.parse <<EOPLT
.section metasmintern_plt r x
metasmintern_pltstart:
	push dword ptr [ebx+4]
	jmp  dword ptr [ebx+8]

metasmintern_pltgetgotebx:
	call metasmintern_pltgetgotebx_foo
metasmintern_pltgetgotebx_foo:
	pop ebx
	add ebx, #{program.label_at(pltgot.edata, 0)} - metasmintern_pltgetgotebx_foo
	ret
EOPLT
		pltsec = program.sections.pop
		end

		program.import.each { |lib, ilist|
			ilist.each { |iname, thunkname|
				if thunkname
					uninit = program.new_unique_label
					program.parse <<EOPLTE
#{thunkname}:
	call metasmintern_pltgetgotebx
	jmp [ebx+#{pltgot.edata.virtsize}]
#{uninit}:
	push #{relplt.edata.virtsize}
	jmp metasmintern_pltstart
align 0x10
EOPLTE
					pltgot.edata.export[iname] = pltgot.edata.virtsize if iname != thunkname
					encoderel[relplt, program.label_at(pltgot.edata, pltgot.edata.virtsize), iname, 'JMP_SLOT']
					encode[pltgot, :u32, uninit]
					# no base relocs
				else
					got.edata.export[iname] = got.edata.virtsize
					encoderel[rel, iname, iname, 'GLOB_DAT']
					encode[got, :u32, 0]
				end
			}
		}
		if pltgot
		pltsec.encode
		plt.edata << pltsec.encoded
		end


		# create misc segments
		if s = sections.find { |s| s.name == '.interp' }
			encode_segm['INTERP',
				s.rawoffset ||= program.new_unique_label,
				program.label_at(s.edata, 0),
				s.edata.virtsize,
				nil,
				['R'],
				s.align]
		end

		if not opts.delete('no_program_header_segment')
			end_phdr ||= program.new_unique_label
			encode_segm['PHDR',
				phdr_s.rawoffset ||= program.new_unique_label,
				program.label_at(phdr, 0),
				[end_phdr, :-, program.label_at(phdr, 0)],
				nil,
				['R'],
				phdr_s.align
			]
		end


		# create load segments
		# merge sections, try to avoid rwx segment (PaX)
		# TODO enforce noread/nowrite/noexec section specification ?
		# TODO minimize segment with unneeded permissions ? (R R R R R RW R RX R => rw[R R R R R RW R] rx[RX R], could be r[R R R R R] rw[RW] r[R] rx[RX] r[R] (with page-size merges/in-section splitting?))
		aligned = opts.delete('create_aligned_load_segments')
		lastprot = []
		firstsect = lastsect = nil
		encode_load_segment = proc {
			if lastsect.name == :phdr
				# the program header is not complete yet, so we cannot rely on its virtsize/rawsize
				end_phdr ||= program.new_unique_label
				size = virtsize = [end_phdr, :-, program.label_at(firstsect.edata, 0)]
			else
				size = [program.label_at(lastsect.edata, lastsect.edata.rawsize), :-, program.label_at(firstsect.edata, 0)]
				virtsize = [program.label_at(lastsect.edata, lastsect.edata.virtsize), :-, program.label_at(firstsect.edata, 0)]
			end
			if not aligned
				encode_segm['LOAD',
					firstsect.rawoffset ||= program.new_unique_label,
					program.label_at(firstsect.edata, 0),
					size,	# allow virtual data here (will be zeroed on load) XXX check zeroing
					virtsize,
					['R', *{'WRITE' => 'W', 'EXECINSTR' => 'X'}.values_at(*lastprot).compact],
					0x1000
				]
			else
				encode_segm['LOAD',
					[(firstsect.rawoffset ||= program.new_unique_label), :&, 0xffff_f000],
					[program.label_at(firstsect.edata, 0), :&, 0xffff_f000],
					[[[size, :+, [firstsect.rawoffset, :&, 0xfff]], :+, 0xfff], :&, 0xffff_f000],
					[[[virtsize, :+, [firstsect.rawoffset, :&, 0xfff]], :+, 0xfff], :&, 0xffff_f000],
					['R', *{'WRITE' => 'W', 'EXECINSTR' => 'X'}.values_at(*lastprot).compact],
					0x1000
				]
			end
		}
		sections.each { |s|
			xflags = s.flags & %w[EXECINSTR WRITE]	# non mergeable flags
			if not s.flags.include? 'ALLOC'	# ignore
				s.edata.fill
			elsif firstsect and (xflags | lastprot == xflags or xflags.empty?)	# concat for R+RW / RW + R, not for RW+RX (unless last == RWX)
				if lastsect.edata.virtsize > lastsect.edata.rawsize + 0x1000
					# XXX new_seg ?
				end
				lastsect.edata.fill
				lastsect = s
				lastprot |= xflags
			else					# section incompatible with current segment: create new segment (or first section seen)
				if firstsect
					encode_load_segment[]
					s.virt_gap = true
				end
				firstsect = lastsect = s
				lastprot = xflags
			end
		}
		if firstsect	# encode last load segment
			encode_load_segment[]
		end


		(opts.delete('additional_segments') || []).each { |sg| encode_segm[sg['type'], sg['offset'], sg['vaddr'], sg['filesz'], sg['memsz'], sg['flags'], sg['align']] }
		phdr.export[end_phdr] = phdr.virtsize if end_phdr

		hdr = EncodedData.new
		end_hdr = program.new_unique_label
		hdr << 0x7f << 'ELF'
		hdr << CLASS.index(program.cpu.size.to_s)	# 16bits ?
		hdr << DATA.index( {:little => 'LSB', :big => 'MSB'}[program.cpu.endianness] )
		e_version = int_from_hash(opts.delete('e_version') || 'CURRENT', VERSION)
		hdr << e_version
		hdr.fill(16, "\0")

		phdr = sections.find { |s| s.name == :phdr }
		encode[:u32, phdr ? phdr.rawoffset ||= program.new_unique_label : 0]
		shdr = sections.find { |s| s.name == :shdr }
		encode[:u32, shdr ? shdr.rawoffset ||= program.new_unique_label : 0]
		
		encode[:u32, opts.delete('elf_flags') || 0]	# 0 for IA32
		encode[:u16, [end_hdr, :-, program.label_at(hdr, 0)]]
		encode[:u16, 0x20]	# program header entry size
		encode[:u16, phdr ? phdr.edata.virtsize / 0x20 : 0]	# number of program header entries
		encode[:u16, 0x28]	# section header entry size
		encode[:u16, shdr ? shdr.edata.virtsize / 0x28 : 0]	# number of section header entries
		encode[:u16, shdr ? sections.find_all { |s| s.name.kind_of? String }.index(sections.find { |s| s.name == '.shstrtab' }) + 1 : 0]	# index of string table index in section table

		hdr.export[end_hdr] = hdr.virtsize

		sections.unshift(h_s = Section.new)
		h_s.name = :hdr
		h_s.edata = hdr
	end

	def link(program, target, sections, opts)
		virtaddr = opts.delete('prefered_base_adress') || (target == 'EXEC' ? 0x08048000 : 0)
		rawaddr  = 0

		has_segments = sections.find { |s| s.name == :phdr }
		binding = {}
		sections.each { |s|
			if has_segments
				if s.virt_gap
					if virtaddr & 0xfff >= 0xe00
						# small gap: align in file
						virtaddr = (virtaddr + 0xfff) & 0xffff_f000
						rawaddr  = (rawaddr  + 0xfff) & 0xffff_f000
					elsif virtaddr & 0xfff > 0
						# big gap: map page twice
						virtaddr += 0x1000
					end
				end
				if rawaddr & 0xfff != virtaddr & 0xfff
					virtaddr += ((rawaddr & 0xfff) - (virtaddr & 0xfff)) & 0xfff
				end
			end

			if s.align and s.align > 1
				virtaddr = EncodedData.align_size(virtaddr, s.align)
				rawaddr  = EncodedData.align_size(rawaddr,  s.align)
			end

			s.edata.export.each { |name, off| binding[name] = Expression[virtaddr, :+, off] }
			if s.rawoffset
				binding[s.rawoffset] = rawaddr
			else
				s.rawoffset = rawaddr
			end

			virtaddr += s.edata.virtsize if target != 'REL'
			rawaddr  += s.edata.rawsize
		}

		sections.each { |s| s.edata.fixup binding }
		puts 'Unused ELF options: ' << opts.keys.sort_by { |k| k.to_s }.inspect unless opts.empty?
		raise EncodeError, "unresolved relocations: " + sections.map { |s| s.edata.reloc.map { |o, r| r.target.bind(binding).reduce } }.flatten.inspect if sections.find { |s| not s.edata.reloc.empty? }

		sections.inject(EncodedData.new) { |ed, s|
			ed.fill(binding[s.rawoffset] || s.rawoffset)
			ed << s.edata.data
		}.data
	end
end
end
end
