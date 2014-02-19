#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/decode'
require 'metasm/exe_format/elf' unless defined? Metasm::ELF

module Metasm
class ELF
  class Header
    # hook the decode sequence, to fixup elf data based on info
    # we have (endianness & xword size, needed in decode_word etc)
    decode_hook(:type) { |elf, hdr|
      raise InvalidExeFormat, "E: ELF: invalid ELF signature #{hdr.magic.inspect}" if hdr.magic != "\x7fELF"

      case hdr.e_class
      when '32'; elf.bitsize = 32
      when '64', '64_icc'; elf.bitsize = 64
      else puts "W: ELF: unsupported class #{hdr.e_class}, assuming 32bit"; elf.bitsize = 32
      end

      case hdr.data
      when 'LSB'; elf.endianness = :little
      when 'MSB'; elf.endianness = :big
      else puts "W: ELF: unsupported endianness #{hdr.data}, assuming littleendian"; elf.endianness = :little
      end

      if hdr.i_version != 'CURRENT'
        puts ":: ELF: unsupported ELF version #{hdr.i_version}"
      end
    }
  end

  class Symbol
    def decode(elf, strtab=nil)
      super(elf)
      @name = elf.readstr(strtab, @name_p) if strtab
    end
  end

  # basic immediates decoding functions
  def decode_byte( edata = @encoded) edata.decode_imm(:u8,  @endianness) end
  def decode_half( edata = @encoded) edata.decode_imm(:u16, @endianness) end
  def decode_word( edata = @encoded) edata.decode_imm(:u32, @endianness) end
  def decode_sword(edata = @encoded) edata.decode_imm(:i32, @endianness) end
  def decode_xword(edata = @encoded) edata.decode_imm((@bitsize == 32 ? :u32 : :u64), @endianness) end
  def decode_sxword(edata= @encoded) edata.decode_imm((@bitsize == 32 ? :i32 : :i64), @endianness) end
  alias decode_addr decode_xword
  alias decode_off  decode_xword

  def readstr(str, off)
    if off > 0 and i = str.index(?\0, off) rescue false	# LoadedElf with arbitrary pointer...
      str[off...i]
    end
  end

  # transforms a virtual address to a file offset, from mmaped segments addresses
  def addr_to_off(addr)
    s = @segments.find { |s_| s_.type == 'LOAD' and s_.vaddr <= addr and s_.vaddr + s_.memsz > addr } if addr
    addr - s.vaddr + s.offset if s
  end

  # memory address -> file offset
  # handles relocated LoadedELF
  def addr_to_fileoff(addr)
    la = module_address
    la = (la == 0 ? (@load_address ||= 0) : 0)
    addr_to_off(addr - la)
  end

  # file offset -> memory address
  # handles relocated LoadedELF
  def fileoff_to_addr(foff)
    if s = @segments.find { |s_| s_.type == 'LOAD' and s_.offset <= foff and s_.offset + s_.filesz > foff }
      la = module_address
      la = (la == 0 ? (@load_address ||= 0) : 0)
      s.vaddr + la + foff - s.offset
    end
  end

  # return the address of a label
  def label_addr(name)
    if name.kind_of? Integer
      name
    elsif s = @segments.find { |s_| s_.encoded and s_.encoded.export[name] }
      s.vaddr + s.encoded.export[name]
    elsif o = @encoded.export[name] and s = @segments.find { |s_| s_.offset <= o and s_.offset + s_.filesz > o }
      s.vaddr + o - s.offset
    end
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
  def decode_header(off = 0, decode_phdr=true, decode_shdr=true)
    @encoded.ptr = off
    @header.decode self
    raise InvalidExeFormat, "Invalid elf header size: #{@header.ehsize}" if Header.size(self) != @header.ehsize
    if decode_phdr and @header.phoff != 0
      decode_program_header(@header.phoff+off)
    end
    if decode_shdr and @header.shoff != 0
      decode_section_header(@header.shoff+off)
    end
  end

  # decodes the section header
  # section names are read from shstrndx if possible
  def decode_section_header(off = @header.shoff)
    raise InvalidExeFormat, "Invalid elf section header size: #{@header.shentsize}" if Section.size(self) != @header.shentsize
    @encoded.add_export new_label('section_header'), off
    @encoded.ptr = off
    @sections = []
    @header.shnum.times { @sections << Section.decode(self) }

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
    @segments = []
    @header.phnum.times { @segments << Segment.decode(self) }

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
  def check_symbols_gnu_hash(off = @tag['GNU_HASH'], just_get_count=false)
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
    if shift2
    end

    hash_bucket = [] ; hash_bucket_len.times { hash_bucket << decode_word }
    # bucket[N] contains the lowest M for which
    # gnu_hash(sym[M]) % nbuckets == N
    # or 0 if none

    hsymcount = 0
    part4 = []
    hash_bucket.each { |hmodidx|
      # for each bucket, walk all the chain
      # we do not walk the chains in hash_bucket order here, this
      # is just to read all the part4 as we don't know
      # beforehand the number of hashed symbols
      next if hmodidx == 0	# no hash chain for this mod
      loop do
        fu = decode_word
        hsymcount += 1
        part4 << fu
        break if fu & 1 == 1
      end
    }

    # part4[N] contains
    # (gnu_hash(sym[N].name) & ~1) | (N == dynsymcount-1 || (gnu_hash(sym[N].name) % nbucket) != (gnu_hash(sym[N+1].name) % nbucket))
    # that's the hash, with its lower bit replaced by the bool [1 if i am the last sym having my hash as hash]

    # we're going to decode the symbol table, and we just want to get the nr of symbols to read
    if just_get_count
      # index of highest hashed (exported) symbols
      ns = hsymcount+symndx

      # no way to get the number of non-exported symbols from what we have here
      # so we'll decode all relocs and use the largest index we see..
      rels = []
      if @encoded.ptr = @tag['REL'] and @tag['RELENT'] == Relocation.size(self)
        p_end = @encoded.ptr + @tag['RELSZ']
        while @encoded.ptr < p_end
          rels << Relocation.decode(self)
        end
      end
      if @encoded.ptr = @tag['RELA'] and @tag['RELAENT'] == RelocationAddend.size(self)
        p_end = @encoded.ptr + @tag['RELASZ']
        while @encoded.ptr < p_end
          rels << RelocationAddend.decode(self)
        end
      end
      if @encoded.ptr = @tag['JMPREL'] and relcls = case @tag['PLTREL']
          when 'REL';  Relocation
          when 'RELA'; RelocationAddend
          end
        p_end = @encoded.ptr + @tag['PLTRELSZ']
        while @encoded.ptr < p_end
          rels << relcls.decode(self)
        end
      end
      maxr = rels.map { |rel| rel.symbol }.grep(::Integer).max || -1

      return [ns, maxr+1].max
    end


    # TODO
  end

  # read dynamic tags array
  def decode_tags(off = nil)
    if not off
      if s = @segments.find { |s_| s_.type == 'DYNAMIC' }
        # this way it also works with LoadedELF
        off = addr_to_off(s.vaddr)
      elsif s = @sections.find { |s_| s_.type == 'DYNAMIC' }
        # if no DYNAMIC segment, assume we decode an ET_REL from file
        off = s.offset
      end
    end
    return if not @encoded.ptr = off

    @tag = {}
    loop do
      tag = decode_sxword
      val = decode_xword
      if tag >= DYNAMIC_TAG_LOPROC and tag < DYNAMIC_TAG_HIPROC
        tag = int_to_hash(tag-DYNAMIC_TAG_LOPROC, DYNAMIC_TAG_PROC[@header.machine] || {})
        tag += DYNAMIC_TAG_LOPROC if tag.kind_of? Integer
      else
        tag = int_to_hash(tag, DYNAMIC_TAG)
      end
      case tag
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

  # marks a symbol as @encoded.export (from s.value, using segments or sections)
  def decode_symbol_export(s)
    if s.name and s.shndx != 'UNDEF' and %w[NOTYPE OBJECT FUNC].include?(s.type)
      if @header.type == 'REL'
        sec = @sections[s.shndx]
        o = sec.offset + s.value
      elsif not o = addr_to_off(s.value)
        # allow to point to end of segment
        if not seg = @segments.find { |seg_| seg_.type == 'LOAD' and seg_.vaddr + seg_.memsz == s.value }	# check end
          puts "W: Elf: symbol points to unmmaped space (#{s.inspect})" if $VERBOSE and s.shndx != 'ABS'
          return
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
      sym_count = check_symbols_gnu_hash(@tag['GNU_HASH'], true)
    end

    strtab = @encoded[@tag['STRTAB'], @tag['STRSZ']].data.to_str

    @encoded.ptr = @tag['SYMTAB']
    @symbols.clear
    sym_count.times {
      s = Symbol.decode(self, strtab)
      @symbols << s
      decode_symbol_export(s)
    }

    check_symbols_hash if $VERBOSE
    check_symbols_gnu_hash if $VERBOSE
  end

  # decode SYMTAB sections
  def decode_sections_symbols
    @symbols ||= []
    @sections.to_a.each { |sec|
      next if sec.type != 'SYMTAB'
      next if not strtab = @sections[sec.link]
      strtab = @encoded[strtab.offset, strtab.size].data
      @encoded.ptr = sec.offset
      syms = []
      raise 'Invalid symbol table' if sec.size > @encoded.length
      (sec.size / Symbol.size(self)).times { syms << Symbol.decode(self, strtab) }
      alreadysegs = true if @header.type == 'DYN' or @header.type == 'EXEC'
      alreadysyms = @symbols.inject({}) { |h, s| h.update s.name => true } if alreadysegs
      syms.each { |s|
        if alreadysegs
          # if we already decoded the symbols from the DYNAMIC segment,
          # ignore dups and imports from this section
          next if s.shndx == 'UNDEF'
          next if alreadysyms[s.name]
          alreadysyms[s.name] = true
        end
        @symbols << s
        decode_symbol_export(s)
      }
    }
  end

  # decode REL/RELA sections
  def decode_sections_relocs
    @relocations ||= []
    @sections.to_a.each { |sec|
      case sec.type
      when 'REL'; relcls = Relocation
      when 'RELA'; relcls = RelocationAddend
      else next
      end
      startidx = @relocations.length
      @encoded.ptr = sec.offset
      while @encoded.ptr < sec.offset + sec.size
        @relocations << relcls.decode(self)
      end

      # create edata relocs
      tsec = @sections[sec.info]
      relocproc = "arch_decode_segments_reloc_#{@header.machine.to_s.downcase}"
      next if not respond_to? relocproc
      new_label('pcrel')
      @relocations[startidx..-1].each { |r|
        o = @encoded.ptr = tsec.offset + r.offset
        r = r.dup
        l = new_label('pcrel')
        r.offset = Expression[l]
        if rel = send(relocproc, r)
          @encoded.reloc[o] = rel
        end
      }
    }
  end

  # decode relocation tables (REL, RELA, JMPREL) from @tags
  def decode_segments_relocs
    @relocations.clear
    if @encoded.ptr = @tag['REL']
      raise "E: ELF: unsupported rel entry size #{@tag['RELENT']}" if @tag['RELENT'] != Relocation.size(self)
      p_end = @encoded.ptr + @tag['RELSZ']
      while @encoded.ptr < p_end
        @relocations << Relocation.decode(self)
      end
    end

    if @encoded.ptr = @tag['RELA']
      raise "E: ELF: unsupported rela entry size #{@tag['RELAENT'].inspect}" if @tag['RELAENT'] != RelocationAddend.size(self)
      p_end = @encoded.ptr + @tag['RELASZ']
      while @encoded.ptr < p_end
        @relocations << RelocationAddend.decode(self)
      end
    end

    if @encoded.ptr = @tag['JMPREL']
      case reltype = @tag['PLTREL']
      when 'REL';  relcls = Relocation
      when 'RELA'; relcls = RelocationAddend
      else raise "E: ELF: unsupported plt relocation type #{reltype}"
      end
      p_end = @encoded.ptr + @tag['PLTRELSZ']
      while @encoded.ptr < p_end
        @relocations << relcls.decode(self)
      end
    end
  end

  # use relocations as self.encoded.reloc
  def decode_segments_relocs_interpret
    relocproc = "arch_decode_segments_reloc_#{@header.machine.to_s.downcase}"
    if not respond_to? relocproc
      puts "W: Elf: relocs for arch #{@header.machine} unsupported" if $VERBOSE
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

    if @header.machine == 'MIPS' and @tag['PLTGOT'] and @tag['GOTSYM'] and @tag['LOCAL_GOTNO']
      puts "emulating mips PLT-like relocs" if $VERBOSE
      wsz = @bitsize/8
      dyntab = label_addr(@tag['PLTGOT']) - (@tag['GOTSYM'] - @tag['LOCAL_GOTNO']) * wsz
      dt_o = addr_to_off(dyntab)
      @symbols.each_with_index { |sym, i|
        next if i < @tag['GOTSYM'] or not sym.name
        r = Metasm::Relocation.new(Expression[sym.name], "u#@bitsize".to_sym, @endianness)
        @encoded.reloc[dt_o + wsz*i] = r
      }
    end
  end

  # returns the target of a relocation using reloc.symbol
  # may create new labels if the relocation targets a section
  def reloc_target(reloc)
    target = 0
    if reloc.symbol.kind_of?(Symbol)
      if reloc.symbol.type == 'SECTION'
        s = @sections[reloc.symbol.shndx]
        if not target = @encoded.inv_export[s.offset]
          target = new_label(s.name)
          @encoded.add_export(target, s.offset)
        end
      elsif reloc.symbol.name
        target = reloc.symbol.name
      end
    end
    target
  end

  # returns the Metasm::Relocation that should be applied for reloc
  # self.encoded.ptr must point to the location that will be relocated (for implicit addends)
  def arch_decode_segments_reloc_386(reloc)
    if reloc.symbol.kind_of?(Symbol) and n = reloc.symbol.name and reloc.symbol.shndx == 'UNDEF' and @sections and
      s = @sections.find { |s_| s_.name and s_.offset <= @encoded.ptr and s_.offset + s_.size > @encoded.ptr }
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
          label = new_label("xref_#{Expression[target]}")
          @encoded.add_export label, o
        end
        target = label
      else
        puts "W: Elf: relocation pointing out of mmaped space #{reloc.inspect}" if $VERBOSE
      end
    when 'GLOB_DAT', 'JMP_SLOT', '32', 'PC32', 'TLS_TPOFF', 'TLS_TPOFF32'
      # XXX use versionned version
      # lazy jmp_slot ?
      target = reloc_target(reloc)
      target = Expression[target, :-, reloc.offset] if reloc.type == 'PC32'
      target = Expression[target, :+, addend] if addend and addend != 0
      target = Expression[target, :+, 'tlsoffset'] if reloc.type == 'TLS_TPOFF'
      target = Expression[:-, [target, :+, 'tlsoffset']] if reloc.type == 'TLS_TPOFF32'
    when 'COPY'
      # mark the address pointed as a copy of the relocation target
      if not reloc.symbol.kind_of?(Symbol) or not name = reloc.symbol.name
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
    if reloc.symbol.kind_of?(Symbol) and n = reloc.symbol.name and reloc.symbol.shndx == 'UNDEF' and @sections and
      s = @sections.find { |s_| s_.name and s_.offset <= @encoded.ptr and s_.offset + s_.size > @encoded.ptr }
      @encoded.add_export(new_label("#{s.name}_#{n}"), @encoded.ptr, true)
    end

    original_word = decode_word

    # decode addend if needed
    case reloc.type
    when 'NONE' # no addend
    else addend = reloc.addend || Expression.make_signed(original_word, 32)
    end

    case reloc.type
    when 'NONE'
    when '32', 'REL32'
      target = reloc_target(reloc)
      target = Expression[target, :-, reloc.offset] if reloc.type == 'REL32'
      target = Expression[target, :+, addend] if addend and addend != 0
    when '26'
      target = reloc_target(reloc)
      addend &= 0x3ff_ffff
      target = Expression[target, :+, [addend, :<<, 2]] if addend and addend != 0
      target = Expression[[original_word, :&, 0xfc0_0000], :|, [[target, :&, 0x3ff_ffff], :>>, 2]]
    when 'HI16'
      target = reloc_target(reloc)
      addend &= 0xffff
      target = Expression[target, :+, [addend, :<<, 16]] if addend and addend != 0
      target = Expression[[original_word, :&, 0xffff_0000], :|, [[target, :>>, 16], :&, 0xffff]]
    when 'LO16'
      target = reloc_target(reloc)
      addend &= 0xffff
      target = Expression[target, :+, addend] if addend and addend != 0
      target = Expression[[original_word, :&, 0xffff_0000], :|, [target, :&, 0xffff]]
    else
      puts "W: Elf: unhandled MIPS reloc #{reloc.inspect}" if $VERBOSE
      target = nil
    end

    Metasm::Relocation.new(Expression[target], :u32, @endianness) if target
  end

  # returns the Metasm::Relocation that should be applied for reloc
  # self.encoded.ptr must point to the location that will be relocated (for implicit addends)
  def arch_decode_segments_reloc_x86_64(reloc)
    if reloc.symbol.kind_of?(Symbol) and n = reloc.symbol.name and reloc.symbol.shndx == 'UNDEF' and @sections and
      s = @sections.find { |s_| s_.name and s_.offset <= @encoded.ptr and s_.offset + s_.size > @encoded.ptr }
      @encoded.add_export(new_label("#{s.name}_#{n}"), @encoded.ptr, true)
    end

    # decode addend if needed
    case reloc.type
    when 'NONE' # no addend
    when '32', 'PC32'; addend = reloc.addend || decode_sword
    else addend = reloc.addend || decode_sxword
    end

    sz = :u64
    case reloc.type
    when 'NONE'
    when 'RELATIVE'
      # base = @segments.find_all { |s| s.type == 'LOAD' }.map { |s| s.vaddr }.min & 0xffff_f000
      # compiled to be loaded at seg.vaddr
      target = addend
      if o = addr_to_off(target)
        if not label = @encoded.inv_export[o]
          label = new_label("xref_#{Expression[target]}")
          @encoded.add_export label, o
        end
        target = label
      else
        puts "W: Elf: relocation pointing out of mmaped space #{reloc.inspect}" if $VERBOSE
      end
    when 'GLOB_DAT', 'JMP_SLOT', '64', 'PC64', '32', 'PC32'
      # XXX use versionned version
      # lazy jmp_slot ?
      target = reloc_target(reloc)
      target = Expression[target, :-, reloc.offset] if reloc.type == 'PC64' or reloc.type == 'PC32'
      target = Expression[target, :+, addend] if addend and addend != 0
      sz = :u32 if reloc.type == '32' or reloc.type == 'PC32'
    when 'COPY'
      # mark the address pointed as a copy of the relocation target
      if not reloc.symbol.kind_of?(Symbol) or not name = reloc.symbol.name
        puts "W: Elf: symbol to COPY has no name: #{reloc.inspect}" if $VERBOSE
        name = ''
      end
      name = new_label("copy_of_#{name}")
      @encoded.add_export name, @encoded.ptr
      target = nil
    else
      puts "W: Elf: unhandled X86_64 reloc #{reloc.inspect}" if $VERBOSE
      target = nil
    end

    Metasm::Relocation.new(Expression[target], sz, @endianness) if target
  end

  def arch_decode_segments_reloc_sh(reloc)
    if reloc.symbol.kind_of?(Symbol) and n = reloc.symbol.name and reloc.symbol.shndx == 'UNDEF' and @sections and
      s = @sections.find { |s_| s_.name and s_.offset <= @encoded.ptr and s_.offset + s_.size > @encoded.ptr }
      @encoded.add_export(new_label("#{s.name}_#{n}"), @encoded.ptr, true)
    end

    original_word = decode_word

    # decode addend if needed
    case reloc.type
    when 'NONE' # no addend
    else addend = reloc.addend || Expression.make_signed(original_word, 32)
    end

    case reloc.type
    when 'NONE'
    when 'GLOB_DAT', 'JMP_SLOT'
      target = reloc_target(reloc)
      target = Expression[target, :+, addend] if addend and addend != 0
    else
      puts "W: Elf: unhandled SH reloc #{reloc.inspect}" if $VERBOSE
      target = nil
    end

    Metasm::Relocation.new(Expression[target], :u32, @endianness) if target
  end

  class DwarfDebug
    # decode a DWARF2 'compilation unit'
    def decode(elf, info, abbrev, str)
      super(elf, info)
      len = @cu_len-7	# @cu_len is size from end of @cu_len field, so we substract ptsz/tag/abroff
      info.ptr += len	# advance for caller
      info = info[info.ptr-len, len]	# we'll work on our segment
      abbrev.ptr = @abbrev_off

      return if abbrev.ptr >= abbrev.length or info.ptr >= info.length

      idx_abbroff = {}

      # returns a list of siblings at current abbrev.ptr
      decode_tree = lambda { |parent|
        siblings = []
        loop {
          info_idx = elf.decode_leb(info)
          break siblings if info_idx == 0
          abbrev.ptr = idx_abbroff[info_idx] if idx_abbroff[info_idx]
          idx_abbroff[info_idx] ||= abbrev.ptr
          n = DwarfDebug::Node.decode(elf, info, abbrev, str, idx_abbroff)
          idx_abbroff[info_idx+1] ||= abbrev.ptr
          siblings << n
          n.children = decode_tree[n] if n.has_child == 1
          n.parent = parent
          break n if not parent
        }
      }
      @tree = decode_tree[nil]
    end

    class Node
      def decode(elf, info, abbrev, str, idx_abbroff)
        super(elf, abbrev)
        return if @index == 0
        @attributes = []
        loop {
          a = Attribute.decode(elf, abbrev)
          break if a.attr == 0 and a.form == 0
          if a.form == 'INDIRECT'	# actual form tag is stored in info
            a.form = elf.decode_leb(info)
            a.form = DWARF_FORM[a.form] || a.form	# XXX INDIRECT again ?
          end
          a.data = case a.form
          when 'ADDR'; elf.decode_xword(info)	# should use dbg.ptr_sz
          when 'DATA1', 'REF1', 'BLOCK1', 'FLAG'; elf.decode_byte(info)
          when 'DATA2', 'REF2', 'BLOCK2'; elf.decode_half(info)
          when 'DATA4', 'REF4', 'BLOCK4'; elf.decode_word(info)
          when 'DATA8', 'REF8', 'BLOCK8'; elf.decode_word(info) | (elf.decode_word(info) << 32)
          when 'SDATA', 'UDATA', 'REF_UDATA', 'BLOCK'; elf.decode_leb(info)
          when 'STRING'; elf.decode_strz(info)
          when 'STRP'; str.ptr = elf.decode_word(info) ; elf.decode_strz(str)
          end
          case a.form
          when /^REF/
          when /^BLOCK/; a.data = info.read(a.data)
          end
          @attributes << a
        }
      end
    end
  end

  # decode an ULEB128 (dwarf2): read bytes while high bit is set, littleendian
  def decode_leb(ed = @encoded)
    v = s = 0
    loop {
      b = ed.read(1).unpack('C').first.to_i
      v |= (b & 0x7f) << s
      s += 7
      break v if (b&0x80) == 0
    }
  end

  # decodes the debugging information if available
  # only a subset of DWARF2/3 is handled right now
  # most info taken from http://ratonland.org/?entry=39 & libdwarf/dwarf.h
  def decode_debug
    return if not @sections

    # assert presence of DWARF sections
    info = @sections.find { |sec| sec.name == '.debug_info' }
    abbrev = @sections.find { |sec| sec.name == '.debug_abbrev' }
    str = @sections.find { |sec| sec.name == '.debug_str' }
    return if not info or not abbrev

    # section -> content
    info = @encoded[info.offset, info.size]
    abbrev = @encoded[abbrev.offset, abbrev.size]
    str = @encoded[str.offset, str.size] if str

    @debug = []

    while info.ptr < info.length
      @debug << DwarfDebug.decode(self, info, abbrev, str)
    end
  end

  # decodes the ELF dynamic tags, interpret them, and decodes symbols and relocs
  def decode_segments_dynamic(decode_relocs=true)
    return if not dynamic = @segments.find { |s| s.type == 'DYNAMIC' }
    @encoded.ptr = add_label('dynamic_tags', dynamic.vaddr)
    decode_tags
    decode_segments_tags_interpret
    decode_segments_symbols
    return if not decode_relocs
    decode_segments_relocs
    decode_segments_relocs_interpret
  end

  # decodes the dynamic segment, fills segments.encoded
  def decode_segments
    decode_segments_dynamic
    decode_sections_symbols
    #decode_debug	# too many info, decode on demand
    @segments.each { |s|
      case s.type
      when 'LOAD', 'INTERP'
        sz = s.filesz
        pagepad = (-(s.offset + sz)) % 4096
        s.encoded = @encoded[s.offset, sz] || EncodedData.new
        if s.type == 'LOAD' and sz > 0 and not s.flags.include?('W')
          # align loaded data to the next page boundary for readonly mmap
          # but discard the labels/relocs etc
          s.encoded << @encoded[s.offset+sz, pagepad].data rescue nil
          s.encoded.virtsize = sz+pagepad
        end
        s.encoded.virtsize = s.memsz if s.memsz > s.encoded.virtsize
      end
    }
  end

  # decodes sections, interprets symbols/relocs, fills sections.encoded
  def decode_sections
    @symbols.clear	# the NULL symbol is explicit in the symbol table
    decode_sections_symbols
    decode_sections_relocs
    @sections.each { |s|
      case s.type
      when 'PROGBITS', 'NOBITS'
      when 'TODO'	# TODO
      end
    }
    @sections.find_all { |s| s.type == 'PROGBITS' or s.type == 'NOBITS' }.each { |s|
      if s.flags.include? 'ALLOC'
        if s.type == 'NOBITS'
          s.encoded = EncodedData.new '', :virtsize => s.size
        else
          s.encoded = @encoded[s.offset, s.size] || EncodedData.new
          s.encoded.virtsize = s.size
        end
      end
    }
  end

  def decode_exports
    decode_segments_dynamic(false)
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
    return if @header.type != 'REL'
    @sections.each { |s|
      next if not s.encoded
      if not l = s.encoded.inv_export[0] or l != s.name.tr('^a-zA-Z0-9_', '_')
        l = new_label(s.name)
        s.encoded.add_export l, 0
      end
      yield s.encoded, l
    }
  end

  # returns a metasm CPU object corresponding to +header.machine+
  def cpu_from_headers
    case @header.machine
    when 'X86_64'; X86_64.new
    when '386'; Ia32.new
    when 'MIPS'; (@header.flags.include?('32BITMODE') ? MIPS64 : MIPS).new @endianness
    when 'PPC'; PPC.new
    when 'ARM'; ARM.new
    when 'SH'; Sh4.new
    else raise "unsupported cpu #{@header.machine}"
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
    if s = @segments.find { |s_| s_.vaddr == addr }
      "\n// ELF segment at #{Expression[addr]}, flags = #{s.flags.sort.join(', ')}"
    else super(addr, edata)
    end
  end

  # returns a disassembler with a special decodedfunction for dlsym, __libc_start_main, and a default function (i386 only)
  def init_disassembler
    d = super()
    d.backtrace_maxblocks_data = 4
    if d.get_section_at(0)
      # fixes call [constructor] => 0
      d.decoded[0] = true
      d.function[0] = @cpu.disassembler_default_func
    end
    case @cpu.shortname
    when 'ia32', 'x64'
      old_cp = d.c_parser
      d.c_parser = nil
      d.parse_c <<EOC
void *dlsym(int, char *);	// has special callback
// gcc's entrypoint, need pointers to reach main exe code (last callback)
void __libc_start_main(void(*)(), int, int, void(*)(), void(*)()) __attribute__((noreturn));
// standard noreturn, optimized by gcc
void __attribute__((noreturn)) exit(int);
void _exit __attribute__((noreturn))(int);
void abort(void) __attribute__((noreturn));
void __stack_chk_fail __attribute__((noreturn))(void);
EOC
      d.function[Expression['dlsym']] = dls = @cpu.decode_c_function_prototype(d.c_parser, 'dlsym')
      d.function[Expression['__libc_start_main']] = @cpu.decode_c_function_prototype(d.c_parser, '__libc_start_main')
      d.function[Expression['exit']] = @cpu.decode_c_function_prototype(d.c_parser, 'exit')
      d.function[Expression['_exit']] = @cpu.decode_c_function_prototype(d.c_parser, '_exit')
      d.function[Expression['abort']] = @cpu.decode_c_function_prototype(d.c_parser, 'abort')
      d.function[Expression['__stack_chk_fail']] = @cpu.decode_c_function_prototype(d.c_parser, '__stack_chk_fail')
      d.c_parser = old_cp
      dls.btbind_callback = lambda { |dasm, bind, funcaddr, calladdr, expr, origin, maxdepth|
        sz = @cpu.size/8
        raise 'dlsym call error' if not dasm.decoded[calladdr]
        if @cpu.shortname == 'x64'
          arg2 = :rsi
        else
          arg2 = Indirection.new(Expression[:esp, :+, 2*sz], sz, calladdr)
        end
        fnaddr = dasm.backtrace(arg2, calladdr, :include_start => true, :maxdepth => maxdepth)
        if fnaddr.kind_of? ::Array and fnaddr.length == 1 and s = dasm.get_section_at(fnaddr.first) and fn = s[0].read(64) and i = fn.index(?\0) and i > sz	# try to avoid ordinals
          bind = bind.merge @cpu.register_symbols[0] => Expression[fn[0, i]]
        end
        bind
      }
      df = d.function[:default] = @cpu.disassembler_default_func
      df.backtrace_binding[@cpu.register_symbols[4]] = Expression[@cpu.register_symbols[4], :+, @cpu.size/8]
      df.btbind_callback = nil
    when 'mips'
      (d.address_binding[@header.entry] ||= {})[:$t9] ||= Expression[@header.entry]
      @symbols.each { |s|
        next if s.shndx == 'UNDEF' or s.type != 'FUNC'
        (d.address_binding[s.value] ||= {})[:$t9] ||= Expression[s.value]
      }
      d.function[:default] = @cpu.disassembler_default_func
    when 'sh4'
      noret = DecodedFunction.new
      noret.noreturn = true
      %w[__stack_chk_fail abort exit].each { |fn|
        d.function[Expression[fn]] = noret
      }
      d.function[:default] = @cpu.disassembler_default_func
    end
    d
  end

  # returns an array of [name, addr, length, info]
  def section_info
    if @sections
      @sections[1..-1].map { |s|
        [s.name, s.addr, s.size, s.flags.join(',')]
      }
    else
      @segments.map { |s|
        [nil, s.vaddr, s.memsz, s.flags.join(',')]
      }
    end
  end

  def module_name
    @tag and @tag['SONAME']
  end

  def module_address
    @segments.map { |s_| s_.vaddr if s_.type == 'LOAD' }.compact.min || 0
  end

  def module_size
    return 0 if not s = @segments.to_a.reverse.map { |s_| s_.vaddr + s_.memsz if s_.type == 'LOAD' }.compact.max
    s - module_address
  end

  def module_symbols
    syms = []
    m_addr = module_address
    syms << ['entrypoint', @header.entry-m_addr] if @header.entry != 0 or @header.type == 'EXEC'
    @symbols.each { |s|
      next if not s.name or s.shndx == 'UNDEF'
      pfx = %w[LOCAL WEAK].include?(s.bind) ? s.bind.downcase + '_' : ''
      syms << [pfx+s.name, s.value-m_addr, s.size]
    }
    syms
  end
end

class LoadedELF
  # decodes the dynamic segment, fills segments.encoded
  def decode_segments
    if @load_address == 0 and @segments.find { |s| s.type == 'LOAD' and s.vaddr > @encoded.length }
      @load_address = @segments.find_all { |s| s.type == 'LOAD' }.map { |s| s.vaddr }.min
    end
    decode_segments_dynamic
    @segments.each { |s|
      if s.type == 'LOAD'
        s.encoded = @encoded[addr_to_off(s.vaddr), s.memsz]
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
