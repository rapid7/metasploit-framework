#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/encode'
require 'metasm/exe_format/elf' unless defined? Metasm::ELF

module Metasm
class ELF
  class Header
    def set_default_values elf
      @magic     ||= "\x7fELF"
      @e_class   ||= elf.bitsize.to_s
      @data      ||= (elf.endianness == :big ? 'MSB' : 'LSB')
      @version   ||= 'CURRENT'
      @i_version ||= @version
      @entry     ||= 0
      @phoff     ||= elf.segments.empty? ? 0 : elf.new_label('phdr')
      @shoff     ||= elf.sections.length <= 1 ? 0 : elf.new_label('shdr')
      @flags     ||= []
      @ehsize    ||= Header.size(elf)
      @phentsize ||= Segment.size(elf)
      @phnum     ||= elf.segments.length
      @shentsize ||= Section.size(elf)
      @shnum     ||= elf.sections.length

      super(elf)
    end
  end

  class Section
    def set_default_values elf
      make_name_p elf if name and @name != ''
      @flags  ||= []
      @addr   ||= (encoded and @flags.include?('ALLOC')) ? elf.label_at(@encoded, 0) : 0
      @offset ||= encoded ? elf.new_label('section_offset') : 0
      @size   ||= encoded ? @encoded.length : 0
      @addralign ||= entsize || 0
      @entsize ||= @addralign
      @link = elf.sections.index(@link) if link.kind_of? Section
      @info = elf.sections.index(@info) if info.kind_of? Section
      super(elf)
    end

    # defines the @name_p field from @name and elf.section[elf.header.shstrndx]
    # creates .shstrtab if needed
    def make_name_p elf
      return 0 if not name or @name == '' or elf.header.shnum == 0
      if elf.header.shstrndx.to_i == 0 or not elf.sections[elf.header.shstrndx]
        sn = Section.new
        sn.name = '.shstrtab'
        sn.type = 'STRTAB'
        sn.flags = []
        sn.addralign = 1
        sn.encoded = EncodedData.new << 0
        elf.header.shstrndx = elf.sections.length
        elf.sections << sn
      end
      sne = elf.sections[elf.header.shstrndx].encoded
      return if name_p and sne.data[@name_p, @name.length+1] == @name+0.chr
      return if @name_p = sne.data.index(@name+0.chr)
      @name_p = sne.virtsize
      sne << @name << 0
    end
  end

  class Segment
    def set_default_values elf
      if encoded
        @offset ||= elf.new_label('segment_offset')
        @vaddr  ||= elf.label_at(@encoded, 0)
        @filesz ||= @encoded.rawsize
        @memsz  ||= @encoded.virtsize
      end
      @paddr  ||= @vaddr if vaddr

      super(elf)
    end
  end

  class Symbol
    def set_default_values(elf, strtab)
      make_name_p elf, strtab if strtab and name and @name != ''
      super(elf)
    end

    # sets the value of @name_p, appends @name to strtab if needed
    def make_name_p(elf, strtab)
      s = strtab.kind_of?(EncodedData) ? strtab.data : strtab
      return if name_p and s[@name_p, @name.length+1] == @name+0.chr
      return if @name_p = s.index(@name+0.chr)
      @name_p = strtab.length
      strtab << @name << 0
    end
  end


  def encode_byte(w)   Expression[w].encode(:u8,  @endianness, (caller if $DEBUG)) end
  def encode_half(w)   Expression[w].encode(:u16, @endianness, (caller if $DEBUG)) end
  def encode_word(w)   Expression[w].encode(:u32, @endianness, (caller if $DEBUG)) end
  def encode_sword(w)  Expression[w].encode(:i32, @endianness, (caller if $DEBUG)) end
  def encode_xword(w)  Expression[w].encode((@bitsize == 32 ? :u32 : :u64), @endianness, (caller if $DEBUG)) end
  def encode_sxword(w) Expression[w].encode((@bitsize == 32 ? :i32 : :i64), @endianness, (caller if $DEBUG)) end
  alias encode_addr encode_xword
  alias encode_off  encode_xword

  # checks a section's data has not grown beyond s.size, if so undefs addr/offset
  def encode_check_section_size(s)
    if s.size and s.encoded.virtsize < s.size
      puts "W: Elf: preexisting section #{s} has grown, relocating" if $VERBOSE
      s.addr = s.offset = nil
      s.size = s.encoded.virtsize
    end
  end

  # reorders self.symbols according to their gnu_hash
  def encode_reorder_symbols
    gnu_hash_bucket_length = 42	# TODO
    @symbols[1..-1] = @symbols[1..-1].sort_by { |s|
      if s.bind != 'GLOBAL'
        -2
      elsif s.shndx == 'UNDEF' or not s.name
        -1
      else
        ELF.gnu_hash_symbol_name(s.name) % gnu_hash_bucket_length
      end
    }
  end

  # sorted insert of a new section to self.sections according to its permission (for segment merging)
  def encode_add_section s
    # order: r rx rw noalloc
    rank = lambda { |sec|
      f = sec.flags
      sec.type == 'NULL' ? -2 : sec.addr ? -1 :
      f.include?('ALLOC') ? !f.include?('WRITE') ? !f.include?('EXECINSTR') ? 0 : 1 : 2 : 3
    }
    srank = rank[s]
    nexts = @sections.find { |sec| rank[sec] > srank }	# find section with rank superior
    nexts = nexts ? @sections.index(nexts) : -1		# if none, last
    if @header.shstrndx.to_i != 0 and nexts != -1 and @header.shstrndx >= nexts
      @header.shstrndx += 1
    end
    @sections.insert(nexts, s)				# insert section
  end

  # encodes the GNU_HASH table
  # TODO
  def encode_gnu_hash
    return if true

    sortedsyms = @symbols.find_all { |s| s.bind == 'GLOBAL' and s.shndx != 'UNDEF' and s.name }
    bucket = Array.new(42)

    if not gnu_hash = @sections.find { |s| s.type == 'GNU_HASH' }
      gnu_hash = Section.new
      gnu_hash.name = '.gnu.hash'
      gnu_hash.type = 'GNU_HASH'
      gnu_hash.flags = ['ALLOC']
      gnu_hash.entsize = gnu_hash.addralign = 4
      encode_add_section gnu_hash
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

  # encodes the symbol dynamic hash table in the .hash section, updates the HASH tag
  def encode_hash
    return if @symbols.length <= 1

    if not hash = @sections.find { |s| s.type == 'HASH' }
      hash = Section.new
      hash.name = '.hash'
      hash.type = 'HASH'
      hash.flags = ['ALLOC']
      hash.entsize = hash.addralign = 4
      encode_add_section hash
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
      next if s.bind == 'LOCAL' or not s.name or s.shndx == 'UNDEF'
      hash_mod = ELF.hash_symbol_name(s.name) % bucket.length
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

  # encodes the symbol table
  # should have a stable self.sections array (only append allowed after this step)
  def encode_segments_symbols(strtab)
    return if @symbols.length <= 1

    if not dynsym = @sections.find { |s| s.type == 'DYNSYM' }
      dynsym = Section.new
      dynsym.name = '.dynsym'
      dynsym.type = 'DYNSYM'
      dynsym.entsize = Symbol.size(self)
      dynsym.addralign = 4
      dynsym.flags = ['ALLOC']
      dynsym.info = @symbols[1..-1].find_all { |s| s.bind == 'LOCAL' }.length + 1
      dynsym.link = strtab
      encode_add_section dynsym
    end
    dynsym.encoded = EncodedData.new
    @symbols.each { |s| dynsym.encoded << s.encode(self, strtab.encoded) }	# needs all section indexes, as will be in the final section header

    @tag['SYMTAB'] = label_at(dynsym.encoded, 0)
    @tag['SYMENT'] = Symbol.size(self)

    encode_check_section_size dynsym

    dynsym
  end

  # encodes the relocation tables
  # needs a complete self.symbols array
  def encode_segments_relocs
    return if not @relocations or @relocations.empty?

    arch_preencode_reloc_func = "arch_#{@header.machine.downcase}_preencode_reloc"
    send arch_preencode_reloc_func if respond_to? arch_preencode_reloc_func

    list = @relocations.find_all { |r| r.type == 'JMP_SLOT' }
    if not list.empty? or @relocations.empty?
      if list.find { |r| r.addend }
        stype = 'RELA'
        sname = '.rela.plt'
      else
        stype = 'REL'
        sname = '.rel.plt'
      end

      if not relplt = @sections.find { |s| s.type == stype and s.name == sname }
        relplt = Section.new
        relplt.name = sname
        relplt.flags = ['ALLOC']
        encode_add_section relplt
      end
      relplt.encoded = EncodedData.new('', :export => {'_REL_PLT' => 0})
      list.each { |r| relplt.encoded << r.encode(self) }
      @tag['JMPREL'] = label_at(relplt.encoded, 0)
      @tag['PLTRELSZ'] = relplt.encoded.virtsize
      @tag['PLTREL'] = relplt.type = stype
      @tag[stype + 'ENT']  = relplt.entsize = relplt.addralign = (stype == 'REL' ? Relocation.size(self) : RelocationAddend.size(self))
      encode_check_section_size relplt
    end

    list = @relocations.find_all { |r| r.type != 'JMP_SLOT' and not r.addend }
    if not list.empty?
      if not @tag['TEXTREL'] and @sections.find { |s_|
        s_.encoded and e = s_.encoded.inv_export[0] and not s_.flags.include? 'WRITE' and
        list.find { |r| Expression[r.offset, :-, e].reduce.kind_of? ::Integer }
        # TODO need to check with r.offset.bind(elf_binding)
      }
        @tag['TEXTREL'] = 0
      end
      if not rel = @sections.find { |s_| s_.type == 'REL' and s_.name == '.rel.dyn' }
        rel = Section.new
        rel.name = '.rel.dyn'
        rel.type = 'REL'
        rel.flags = ['ALLOC']
        rel.entsize = rel.addralign = Relocation.size(self)
        encode_add_section rel
      end
      rel.encoded = EncodedData.new
      list.each { |r| rel.encoded << r.encode(self) }
      @tag['REL'] = label_at(rel.encoded, 0)
      @tag['RELENT'] = Relocation.size(self)
      @tag['RELSZ'] = rel.encoded.virtsize
      encode_check_section_size rel
    end

    list = @relocations.find_all { |r| r.type != 'JMP_SLOT' and r.addend }
    if not list.empty?
      if not rela = @sections.find { |s_| s_.type == 'RELA' and s_.name == '.rela.dyn' }
        rela = Section.new
        rela.name = '.rela.dyn'
        rela.type = 'RELA'
        rela.flags = ['ALLOC']
        rela.entsize = rela.addralign = RelocationAddend.size(self)
        encode_add_section rela
      end
      rela.encoded = EncodedData.new
      list.each { |r| rela.encoded << r.encode(self) }
      @tag['RELA'] = label_at(rela.encoded, 0)
      @tag['RELAENT'] = RelocationAddend.size(self)
      @tag['RELASZ'] = rela.encoded.virtsize
      encode_check_section_size rela
    end
  end

  # creates the .plt/.got from the @relocations
  def arch_386_preencode_reloc
    return if @relocations.empty?

    # if .got.plt does not exist, the dynamic loader segfaults
    if not gotplt = @sections.find { |s| s.type == 'PROGBITS' and s.name == '.got.plt' }
      gotplt = Section.new
      gotplt.name = '.got.plt'
      gotplt.type = 'PROGBITS'
      gotplt.flags = %w[ALLOC WRITE]
      gotplt.addralign = @bitsize/8
      # _DYNAMIC is not base-relocated at runtime
      encode_add_section gotplt
    end
    gotplt.encoded ||= (EncodedData.new('', :export => {'_PLT_GOT' => 0}) << encode_xword('_DYNAMIC') << encode_xword(0) << encode_xword(0))
    @tag['PLTGOT'] = label_at(gotplt.encoded, 0)
    plt = nil

    shellcode = lambda { |c| Shellcode.new(@cpu).share_namespace(self).assemble(c).encoded }

    @relocations.dup.each { |r|
      case r.type
      when 'PC32'
        next if not r.symbol

        if r.symbol.type != 'FUNC'
          # external data xref: generate a GOT entry
          # XXX reuse .got.plt ?
          if not got ||= @sections.find { |s| s.type == 'PROGBITS' and s.name == '.got' }
            got = Section.new
            got.name = '.got'
            got.type = 'PROGBITS'
            got.flags = %w[ALLOC WRITE]
            got.addralign = @bitsize/8
            got.encoded = EncodedData.new
            encode_add_section got
          end

          prevoffset = r.offset
          gotlabel = r.symbol.name + '_got_entry'
          if not got.encoded.export[gotlabel]
            # create the got thunk
            got.encoded.add_export(gotlabel, got.encoded.length)
            got.encoded << encode_xword(0)

            # transform the reloc PC32 => GLOB_DAT
            r.type = 'GLOB_DAT'
            r.offset = Expression[gotlabel]
            r.addend = 0 if @bitsize == 64
          else
            @relocations.delete r
          end

          # prevoffset is label_section_start + int_section_offset
          target_s = @sections.find { |s| s.encoded and s.encoded.export[prevoffset.lexpr] == 0 }
          rel = target_s.encoded.reloc[prevoffset.rexpr]
          # [foo] => [foo - reloc_addr + gotlabel]

          rel.target = Expression[[rel.target, :-, prevoffset], :+, gotlabel]
          next
        end

        # convert to .plt entry
        #
        # [.plt header]
        # plt_start:			# caller set ebx = gotplt if generate_PIC
        #  push [gotplt+4]
        #  jmp  [gotplt+8]
        #
        # [.plt thunk]
        # some_func_thunk:
        #  jmp  [gotplt+func_got_offset]
        # some_func_got_default:
        #  push some_func_jmpslot_offset_in_.rel.plt
        #  jmp plt_start
        #
        # [.got.plt header]
        # dd _DYNAMIC
        # dd 0				# rewritten to GOTPLT? by ld-linux
        # dd 0				# rewritten to dlresolve_inplace by ld-linux
        #
        # [.got.plt + func_got_offset]
        # dd some_func_got_default	# lazily rewritten to the real addr of some_func by jmp dlresolve_inplace
        #				# base_relocated ?

        # in the PIC case, _dlresolve imposes us to use the ebx register (which may not be saved by the calling function..)
        # also geteip trashes eax, which may interfere with regparm(3)
        base = @cpu.generate_PIC ? @bitsize == 32 ? 'ebx' : 'rip-$_+_PLT_GOT' : '_PLT_GOT'
        if not plt ||= @sections.find { |s| s.type == 'PROGBITS' and s.name == '.plt' }
          plt = Section.new
          plt.name = '.plt'
          plt.type = 'PROGBITS'
          plt.flags = %w[ALLOC EXECINSTR]
          plt.addralign = @bitsize/8
          plt.encoded = EncodedData.new
          sz = @bitsize/8
          ptqual = @bitsize == 32 ? 'dword' : 'qword'
          plt.encoded << shellcode["metasm_plt_start:\npush #{ptqual} ptr [#{base}+#{sz}]\njmp #{ptqual} ptr [#{base}+#{2*sz}]"]
          if @cpu.generate_PIC and @bitsize == 32 and not @sections.find { |s| s.encoded and s.encoded.export['metasm_intern_geteip'] }
            plt.encoded << shellcode["metasm_intern_geteip:\ncall 42f\n42: pop eax\nsub eax, 42b-metasm_intern_geteip\nret"]
          end
          encode_add_section plt
        end

        prevoffset = r.offset
        pltlabel = r.symbol.name + '_plt_thunk'
        if not plt.encoded.export[pltlabel]
          # create the plt thunk
          plt.encoded.add_export pltlabel, plt.encoded.length
          if @cpu.generate_PIC and @bitsize == 32
            plt.encoded << shellcode["call metasm_intern_geteip\nlea #{base}, [eax+_PLT_GOT-metasm_intern_geteip]"]
          end
          plt.encoded << shellcode["jmp [#{base} + #{gotplt.encoded.length}]"]
          plt.encoded.add_export r.symbol.name+'_plt_default', plt.encoded.length
          reloffset = @relocations.find_all { |rr| rr.type == 'JMP_SLOT' }.length
          reloffset *= Relocation.size(self) if @bitsize == 32
          plt.encoded << shellcode["push #{reloffset}\njmp metasm_plt_start"]

          # transform the reloc PC32 => JMP_SLOT
          r.type = 'JMP_SLOT'
          r.offset = Expression['_PLT_GOT', :+, gotplt.encoded.length]
          r.addend = 0 if @bitsize == 64

          gotplt.encoded << encode_xword(r.symbol.name + '_plt_default')
        else
          @relocations.delete r
        end

        # mutate the original relocation
        # XXX relies on the exact form of r.target from arch_create_reloc
        target_s = @sections.find { |s| s.encoded and s.encoded.export[prevoffset.lexpr] == 0 }
        rel = target_s.encoded.reloc[prevoffset.rexpr]
        rel.target = Expression[[[rel.target, :-, prevoffset.rexpr], :-, label_at(target_s.encoded, 0)], :+, pltlabel]

      # when 'GOTOFF', 'GOTPC'
      end
    }
    encode_check_section_size gotplt
    encode_check_section_size plt if plt
    #encode_check_section_size got if got
  end
  alias arch_x86_64_preencode_reloc arch_386_preencode_reloc

  # encodes the .dynamic section, creates .hash/.gnu.hash/.rel/.rela/.dynsym/.strtab/.init,*_array as needed
  def encode_segments_dynamic
    if not strtab = @sections.find { |s| s.type == 'STRTAB' and s.flags.include? 'ALLOC' }
      strtab = Section.new
      strtab.name = '.dynstr'
      strtab.addralign = 1
      strtab.type = 'STRTAB'
      strtab.flags = ['ALLOC']
      encode_add_section strtab
    end
    strtab.encoded = EncodedData.new << 0
    @tag['STRTAB'] = label_at(strtab.encoded, 0)

    if not dynamic = @sections.find { |s| s.type == 'DYNAMIC' }
      dynamic = Section.new
      dynamic.name = '.dynamic'
      dynamic.type = 'DYNAMIC'
      dynamic.flags = %w[WRITE ALLOC]		# XXX why write ?
      dynamic.addralign = dynamic.entsize = @bitsize / 8 * 2
      dynamic.link = strtab
      encode_add_section dynamic
    end
    dynamic.encoded = EncodedData.new('', :export => {'_DYNAMIC' => 0})

    encode_tag = lambda { |k, v|
      dynamic.encoded <<
      encode_sxword(int_from_hash(k, DYNAMIC_TAG)) <<
      encode_xword(v)
    }

    # find or create string in strtab
    add_str = lambda { |n|
      if n and n != '' and not ret = strtab.encoded.data.index(n + 0.chr)
        ret = strtab.encoded.virtsize
        strtab.encoded << n << 0
      end
      ret || 0
    }
    @tag.keys.each { |k|
      case k
      when 'NEEDED'; @tag[k].each { |n| encode_tag[k, add_str[n]] }
      when 'SONAME', 'RPATH', 'RUNPATH'; encode_tag[k, add_str[@tag[k]]]
      when 'INIT_ARRAY', 'FINI_ARRAY', 'PREINIT_ARRAY'	# build section containing the array
        if not ar = @sections.find { |s| s.name == '.' + k.downcase }
          ar = Section.new
          ar.name = '.' + k.downcase
          ar.type = k
          ar.addralign = ar.entsize = @bitsize/8
          ar.flags = %w[WRITE ALLOC]
          ar.encoded = EncodedData.new
          encode_add_section ar # insert before encoding syms/relocs (which need section indexes)
        end

        # fill these later, but create the base relocs now
        arch_create_reloc_func = "arch_#{@header.machine.downcase}_create_reloc"
        next if not respond_to?(arch_create_reloc_func)
        curaddr = label_at(@encoded, 0, 'elf_start')
        fkbind = {}
        @sections.each { |s|
          next if not s.encoded
          fkbind.update s.encoded.binding(Expression[curaddr, :+, 1])
        }
        @relocations ||= []
        off = ar.encoded.length
        @tag[k].each { |a|
          rel = Metasm::Relocation.new(Expression[a], "u#@bitsize".to_sym, @endianness)
          send(arch_create_reloc_func, ar, off, fkbind, rel)
          off += @bitsize/8
        }
      end
    }

    encode_reorder_symbols
    encode_gnu_hash
    encode_hash
    encode_segments_relocs
    dynsym = encode_segments_symbols(strtab)
    @sections.find_all { |s| %w[HASH GNU_HASH REL RELA].include? s.type }.each { |s| s.link = dynsym }

    encode_check_section_size strtab

    # rm unused tag (shrink .nointerp binaries by allowing to skip the section entirely)
    @tag.delete('STRTAB') if strtab.encoded.length == 1

    # XXX any order needed ?
    @tag.keys.each { |k|
      case k
      when Integer	# unknown tags = array of values
        @tag[k].each { |n| encode_tag[k, n] }
      when 'PLTREL';     encode_tag[k, int_from_hash(@tag[k], DYNAMIC_TAG)]
      when 'FLAGS';      encode_tag[k, bits_from_hash(@tag[k], DYNAMIC_FLAGS)]
      when 'FLAGS_1';    encode_tag[k, bits_from_hash(@tag[k], DYNAMIC_FLAGS_1)]
      when 'FEATURES_1'; encode_tag[k, bits_from_hash(@tag[k], DYNAMIC_FEATURES_1)]
      when 'NULL'	# keep last
      when 'STRTAB'
        encode_tag[k, @tag[k]]
        encode_tag['STRSZ', strtab.encoded.size]
      when 'INIT_ARRAY', 'FINI_ARRAY', 'PREINIT_ARRAY'	# build section containing the array
        ar = @sections.find { |s| s.name == '.' + k.downcase }
        @tag[k].each { |p| ar.encoded << encode_addr(p) }
        encode_check_section_size ar
        encode_tag[k, label_at(ar.encoded, 0)]
        encode_tag[k + 'SZ', ar.encoded.virtsize]
      when 'NEEDED', 'SONAME', 'RPATH', 'RUNPATH'	# already handled
      else
        encode_tag[k, @tag[k]]
      end
    }
    encode_tag['NULL', @tag['NULL'] || 0] unless @tag.empty?

    encode_check_section_size dynamic
  end

  # creates the undef symbol list from the section.encoded.reloc and a list of known exported symbols (e.g. from libc)
  # also populates @tag['NEEDED']
  def automagic_symbols
    GNUExports rescue return	# autorequire
    autoexports = GNUExports::EXPORT.dup
    @sections.each { |s|
      next if not s.encoded
      s.encoded.export.keys.each { |e| autoexports.delete e }
    }
    @sections.each { |s|
      next if not s.encoded
      s.encoded.reloc.each_value { |r|
        et = r.target.externals
        extern = et.find_all { |name| autoexports[name] }
        next if extern.length != 1
        symname = extern.first
        if not @symbols.find { |sym| sym.name == symname }
          @tag['NEEDED'] ||= []
          @tag['NEEDED'] |= [autoexports[symname]]
          sym = Symbol.new
          sym.shndx = 'UNDEF'
          sym.type = 'FUNC'
          sym.name = symname
          sym.bind = 'GLOBAL'
          @symbols << sym
        end
      }
    }
  end

  # reads the existing segment/sections.encoded and populate @relocations from the encoded.reloc hash
  def create_relocations
    @relocations = []

    arch_create_reloc_func = "arch_#{@header.machine.downcase}_create_reloc"
    if not respond_to? arch_create_reloc_func
      puts "Elf: create_reloc: unhandled architecture #{@header.machine}" if $VERBOSE
      return
    end

    # create a fake binding with all our own symbols
    # not foolproof, should work in most cases
    curaddr = label_at(@encoded, 0, 'elf_start')
    binding = {'_DYNAMIC' => 0, '_GOT' => 0}	# XXX
    @sections.each { |s|
      next if not s.encoded
      binding.update s.encoded.binding(curaddr)
      curaddr = Expression[curaddr, :+, s.encoded.virtsize]
    }

    @sections.each { |s|
      next if not s.encoded
      s.encoded.reloc.each { |off, rel|
        t = rel.target.bind(binding).reduce
        next if not t.kind_of? Expression	# XXX segment_encode only
        send(arch_create_reloc_func, s, off, binding)
      }
    }
  end

  # references to FUNC symbols are transformed to JMPSLOT relocations (aka call to .plt)
  # TODO ET_REL support
  def arch_386_create_reloc(section, off, binding, rel=nil)
    rel ||= section.encoded.reloc[off]
    if rel.endianness != @endianness or not [:u32, :i32, :a32].include? rel.type
      puts "ELF: 386_create_reloc: ignoring reloc #{rel.target} in #{section.name}: bad reloc type" if $VERBOSE
      return
    end
    startaddr = label_at(@encoded, 0)
    r = Relocation.new
    r.offset = Expression[label_at(section.encoded, 0, 'sect_start'), :+, off]
    if Expression[rel.target, :-, startaddr].bind(binding).reduce.kind_of?(::Integer)
      # this location is relative to the base load address of the ELF
      r.type = 'RELATIVE'
    else
      et = rel.target.externals
      extern = et.find_all { |name| not binding[name] }
      if extern.length != 1
        puts "ELF: 386_create_reloc: ignoring reloc #{rel.target} in #{section.name}: #{extern.inspect} unknown" if $VERBOSE
        return
      end
      if not sym = @symbols.find { |s| s.name == extern.first }
        puts "ELF: 386_create_reloc: ignoring reloc #{rel.target} in #{section.name}: undefined symbol #{extern.first}" if $VERBOSE
        return
      end
      r.symbol = sym
      rel.target = Expression[rel.target, :-, sym.name]
      if rel.target.bind(binding).reduce.kind_of? ::Integer
        r.type = '32'
      elsif Expression[rel.target, :+, label_at(section.encoded, 0)].bind(section.encoded.binding).reduce.kind_of? ::Integer
        rel.target = Expression[[rel.target, :+, label_at(section.encoded, 0)], :+, off]
        r.type = 'PC32'
      # TODO tls ?
      else
        puts "ELF: 386_create_reloc: ignoring reloc #{sym.name} + #{rel.target}: cannot find matching standard reloc type" if $VERBOSE
        return
      end
    end
    @relocations << r
  end

  def arch_x86_64_create_reloc(section, off, binding, rel=nil)
    rel ||= section.encoded.reloc[off]
    if rel.endianness != @endianness or not rel.type.to_s =~ /^[aiu](32|64)$/
      puts "ELF: x86_64_create_reloc: ignoring reloc #{rel.target} in #{section.name}: bad reloc type" if $VERBOSE
      return
    end
    startaddr = label_at(@encoded, 0)
    r = RelocationAddend.new
    r.addend = 0
    r.offset = Expression[label_at(section.encoded, 0, 'sect_start'), :+, off]
    if Expression[rel.target, :-, startaddr].bind(binding).reduce.kind_of?(::Integer)
      # this location is relative to the base load address of the ELF
      if rel.length != 8
        puts "ELF: x86_64_create_reloc: ignoring reloc #{rel.target} in #{section.name}: relative non-x64" if $VERBOSE
        return
      end
      r.type = 'RELATIVE'
    else
      et = rel.target.externals
      extern = et.find_all { |name| not binding[name] }
      if extern.length != 1
        puts "ELF: x86_64_create_reloc: ignoring reloc #{rel.target} in #{section.name}: #{extern.inspect} unknown" if $VERBOSE
        return
      end
      if not sym = @symbols.find { |s| s.name == extern.first }
        puts "ELF: x86_64_create_reloc: ignoring reloc #{rel.target} in #{section.name}: undefined symbol #{extern.first}" if $VERBOSE
        return
      end
      r.symbol = sym
      rel.target = Expression[rel.target, :-, sym.name]
      if rel.target.bind(binding).reduce.kind_of? ::Integer
        r.type = '64'	# XXX check that
      elsif Expression[rel.target, :+, label_at(section.encoded, 0)].bind(section.encoded.binding).reduce.kind_of? ::Integer
        rel.target = Expression[[rel.target, :+, label_at(section.encoded, 0)], :+, off]
        r.type = 'PC32'	# XXX
      # TODO tls ?
      else
        puts "ELF: x86_64_create_reloc: ignoring reloc #{sym.name} + #{rel.target}: cannot find matching standard reloc type" if $VERBOSE
        return
      end
    end
    r.addend = Expression[rel.target]
    #section.encoded.reloc.delete off
    @relocations << r
  end

  def arch_mips_create_reloc(section, off, binding, rel=nil)
    rel ||= section.encoded.reloc[off]
    startaddr = label_at(@encoded, 0)
    r = Relocation.new
    r.offset = Expression[label_at(section.encoded, 0, 'sect_start'), :+, off]
    if Expression[rel.target, :-, startaddr].bind(binding).reduce.kind_of?(::Integer)
      # this location is relative to the base load address of the ELF
      r.type = 'REL32'
    else
      et = rel.target.externals
      extern = et.find_all { |name| not binding[name] }
      if extern.length != 1
        puts "ELF: mips_create_reloc: ignoring reloc #{rel.target} in #{section.name}: #{extern.inspect} unknown" if $VERBOSE
        return
      end
      if not sym = @symbols.find { |s| s.name == extern.first }
        puts "ELF: mips_create_reloc: ignoring reloc #{rel.target} in #{section.name}: undefined symbol #{extern.first}" if $VERBOSE
        return
      end
      r.symbol = sym
      if Expression[rel.target, :-, sym.name].bind(binding).reduce.kind_of?(::Integer)
        rel.target = Expression[rel.target, :-, sym.name]
        r.type = '32'
      elsif Expression[rel.target, :&, 0xffff0000].reduce.kind_of?(::Integer)
        lo = Expression[rel.target, :&, 0xffff].reduce
        lo = lo.lexpr if lo.kind_of?(Expression) and lo.op == :& and lo.rexpr == 0xffff
        if lo.kind_of?(Expression) and lo.op == :>> and lo.rexpr == 16
          r.type = 'HI16'
          rel.target = Expression[rel.target, :&, 0xffff0000]
          # XXX offset ?
        elsif lo.kind_of?(String) or (lo.kind_of(Expression) and lo.op == :+)
          r.type = 'LO16'
          rel.target = Expression[rel.target, :&, 0xffff0000]
          # XXX offset ?
        else
          puts "ELF: mips_create_reloc: ignoring reloc #{lo}: cannot find matching 16 reloc type" if $VERBOSE
          return
        end
      #elsif Expression[rel.target, :+, label_at(section.encoded, 0)].bind(section.encoded.binding).reduce.kind_of? ::Integer
      #	rel.target = Expression[[rel.target, :+, label_at(section.encoded, 0)], :+, off]
      #	r.type = 'PC32'
      else
        puts "ELF: mips_create_reloc: ignoring reloc #{sym.name} + #{rel.target}: cannot find matching standard reloc type" if $VERBOSE
        return
      end
    end
    @relocations << r
  end

  # resets the fields of the elf headers that should be recalculated, eg phdr offset
  def invalidate_header
    @header.shoff = @header.shnum = nil
    @header.phoff = @header.phnum = nil
    @header.shstrndx = nil
    @sections.to_a.each { |s|
      s.name_p = nil
      s.offset = nil
    }
    @segments.to_a.each { |s|
      s.offset = nil
    }
    self
  end

  # put every ALLOC section in a segment, create segments if needed
  # sections with a good offset within a segment are ignored
  def encode_make_segments_from_sections
    # fixed addresses first
    seclist = @sections.find_all { |sec| sec.addr.kind_of? Integer }.sort_by { |sec| sec.addr } | @sections
    seclist.each { |sec|
      next if not sec.flags.to_a.include? 'ALLOC'

      # check if we fit in an existing segment
      loadsegs = @segments.find_all { |seg_| seg_.type == 'LOAD' }

      if sec.addr.kind_of?(::Integer) and seg = loadsegs.find { |seg_|
        seg_.vaddr.kind_of?(::Integer) and seg_.vaddr <= sec.addr and seg_.vaddr + seg_.memsz >= sec.addr + sec.size
      }
        # sections is already inside a segment: we're reencoding an ELF, just patch the section in the segment
        seg.encoded[sec.addr - seg.vaddr, sec.size] = sec.encoded if sec.encoded
        next
      end

      if not seg = loadsegs.find { |seg_|
        sec.flags.to_a.include?('WRITE') == seg_.flags.to_a.include?('W') and
        #sec.flags.to_a.include?('EXECINSTR') == seg_.flags.to_a.include?('X') and
        not seg_.memsz and
        not loadsegs[loadsegs.index(seg_)+1..-1].find { |sseg|
          # check if another segment would overlap if we add the sec to seg_
          o = Expression[sseg.vaddr, :-, [seg_.vaddr, :+, seg_.encoded.length+sec.encoded.length]].reduce
          o.kind_of? ::Integer and o < 0
        }
      }
        # nope, create a new one
        seg = Segment.new
        seg.type = 'LOAD'
        seg.flags = ['R']
        seg.flags << 'W' if sec.flags.include? 'WRITE'
        seg.align = 0x1000
        seg.encoded = EncodedData.new
        seg.offset = new_label('segment_offset')
        seg.vaddr = sec.addr || new_label('segment_address')
        @segments << seg
      end
      seg.flags |= ['X'] if sec.flags.include? 'EXECINSTR'
      seg.encoded.align sec.addralign if sec.addralign
      sec.addr = Expression[seg.vaddr, :+, seg.encoded.length]
      sec.offset = Expression[seg.offset, :+, seg.encoded.length]
      seg.encoded << sec.encoded
    }
  end

  # create the relocations from the sections.encoded.reloc
  # create the dynamic sections
  # put sections/phdr in PT_LOAD segments
  # link
  # TODO support mapped PHDR, obey section-specified base address, handle NOBITS
  #      encode ET_REL
  def encode(type='DYN')
    @header.type ||= {:bin => 'EXEC', :lib => 'DYN', :obj => 'REL'}.fetch(type, type)
    @header.machine ||= case @cpu.shortname
        when 'x64'; 'X86_64'
        when 'ia32'; '386'
        when 'mips'; 'MIPS'
        when 'powerpc'; 'PPC'
        when 'arm'; 'ARM'
        end

    if @header.type == 'REL'
      encode_rel
    else
      encode_elf
    end
  end

  def encode_elf
    @encoded = EncodedData.new
    if @header.type != 'EXEC' or @segments.find { |i| i.type == 'INTERP' }
      # create a .dynamic section unless we are an ET_EXEC with .nointerp
      automagic_symbols
      create_relocations
      encode_segments_dynamic
    end

    @segments.delete_if { |s| s.type == 'INTERP' } if not @header.entry

    encode_make_segments_from_sections

    loadsegs = @segments.find_all { |seg_| seg_.type == 'LOAD' }

    # ensure PT_INTERP is mapped if present
    if interp = @segments.find { |i| i.type == 'INTERP' }
      if not seg = loadsegs.find { |seg_| not seg_.memsz and interp.flags & seg_.flags == interp.flags and
          not loadsegs[loadsegs.index(seg_)+1..-1].find { |sseg|
            o = Expression[sseg.vaddr, :-, [seg_.vaddr, :+, seg_.encoded.length+interp.encoded.length]].reduce
            o.kind_of? ::Integer and o < 0
          }
        }
        seg = Segment.new
        seg.type = 'LOAD'
        seg.flags = interp.flags.dup
        seg.align = 0x1000
        seg.encoded = EncodedData.new
        seg.offset = new_label('segment_offset')
        seg.vaddr = new_label('segment_address')
        loadsegs << seg
        @segments << seg
      end
      interp.vaddr = Expression[seg.vaddr, :+, seg.encoded.length]
      interp.offset = Expression[seg.offset, :+, seg.encoded.length]
      seg.encoded << interp.encoded
      interp.encoded = nil
    end

    # ensure last PT_LOAD is writeable (used for bss)
    seg = loadsegs.last
    if not seg or not seg.flags.include? 'W'
      seg = Segment.new
      seg.type = 'LOAD'
      seg.flags = ['R', 'W']
      seg.encoded = EncodedData.new
      loadsegs << seg
      @segments << seg
    end

    # add dynamic segment
    if ds = @sections.find { |sec| sec.type == 'DYNAMIC' } and ds.encoded.length > 1
      ds.set_default_values self
      seg = Segment.new
      seg.type = 'DYNAMIC'
      seg.flags = ['R', 'W']
      seg.offset = ds.offset
      seg.vaddr = ds.addr
      seg.memsz = seg.filesz = ds.size
      @segments << seg
    end

    # use variables in the first segment descriptor, to allow fixup later
    # (when we'll be able to include the program header)
    if first_seg = loadsegs.first
      first_seg_oaddr = first_seg.vaddr	# section's vaddr depend on oaddr
      first_seg_off   = first_seg.offset
      first_seg.vaddr  = new_label('segvaddr')
      first_seg.offset = new_label('segoff')
      first_seg.memsz  = new_label('segmemsz')
      first_seg.filesz = new_label('segfilsz')
    end

    if first_seg and not @segments.find { |seg_| seg_.type == 'PHDR' }
      phdr = Segment.new
      phdr.type = 'PHDR'
      phdr.flags = first_seg.flags
      phdr.offset = new_label('segoff')
      phdr.vaddr = new_label('segvaddr')
      phdr.filesz = phdr.memsz = new_label('segmemsz')
      @segments.unshift phdr
    end

    # encode section&program headers
    if @header.shnum != 0
      st = @sections.inject(EncodedData.new) { |edata, s| edata << s.encode(self) }
    else
      @header.shoff = @header.shnum = @header.shstrndx = 0
    end
    pt = @segments.inject(EncodedData.new) { |edata, s| edata << s.encode(self) }

    binding = {}
    @encoded << @header.encode(self)
    @encoded.align 8
    binding[@header.phoff] = @encoded.length
    if phdr
      binding[phdr.offset] = @encoded.length
      pt.add_export phdr.vaddr, 0
      binding[phdr.memsz] = pt.length
    end
    @encoded << pt
    @encoded.align 8

    if first_seg
      # put headers into the 1st mmaped segment
      if first_seg_oaddr.kind_of? ::Integer
        # pad headers to align the 1st segment's data
        @encoded.virtsize += (first_seg_oaddr - @encoded.virtsize) & 0xfff
        addr = first_seg_oaddr - @encoded.length
      else
        addr = ((@header.type == 'EXEC') ? 0x08048000 : 0)
        binding[first_seg_oaddr] = addr + @encoded.length
      end
      binding[first_seg_off] = @encoded.length if not first_seg_off.kind_of? ::Integer
      first_seg.encoded = @encoded << first_seg.encoded
      @encoded = EncodedData.new
      binding[first_seg.memsz] = first_seg.encoded.virtsize if not first_seg.memsz.kind_of? ::Integer
      binding[first_seg.filesz] = first_seg.encoded.rawsize if not first_seg.filesz.kind_of? ::Integer
    end

    @segments.each { |seg_|
      next if not seg_.encoded
      if seg_.vaddr.kind_of? ::Integer
        raise "cannot put segment at address #{Expression[seg_.vaddr]} (now at #{Expression[addr]})" if seg_.vaddr < addr
        addr = seg_.vaddr
      else
        binding[seg_.vaddr] = addr
      end
      # ensure seg_.vaddr & page_size == seg_.offset & page_size
      @encoded.virtsize += (addr - @encoded.virtsize) & 0xfff
      binding.update seg_.encoded.binding(addr)
      binding[seg_.offset] = @encoded.length
      seg_.encoded.align 8
      @encoded << seg_.encoded[0, seg_.encoded.rawsize]
      addr += seg_.encoded.length

      # page break for memory permission enforcement
      if @segments[@segments.index(seg_)+1..-1].find { |seg__| seg__.encoded and seg__.vaddr.kind_of? ::Integer }
        addr += 0x1000 - (addr & 0xfff) if addr & 0xfff != 0 # minimize memory size
      else
        addr += 0x1000 # minimize file size
      end
    }

    binding[@header.shoff] = @encoded.length if st
    @encoded << st
    @encoded.align 8

    @sections.each { |sec|
      next if not sec.encoded or sec.flags.include? 'ALLOC'	# already in a segment.encoded
      binding[sec.offset] = @encoded.length
      binding.update sec.encoded.binding
      @encoded << sec.encoded
      @encoded.align 8
    }

    @encoded.fixup! binding
    @encoded.data
  end

  def encode_rel
    @encoded = EncodedData.new
    automagic_symbols
    create_relocations

    @header.phoff = @header.phnum = @header.phentsize = 0
    @header.entry = 0
    @sections.each { |sec| sec.addr = 0 }
    st = @sections.inject(EncodedData.new) { |edata, sec| edata << sec.encode(self) }

    binding = {}
    @encoded << @header.encode(self)
    @encoded.align 8

    binding[@header.shoff] = @encoded.length
    @encoded << st
    @encoded.align 8

    @sections.each { |sec|
      next if not sec.encoded
      binding[sec.offset] = @encoded.length
      sec.encoded.fixup sec.encoded.binding
      @encoded << sec.encoded
      @encoded.align 8
    }

    @encoded.fixup! binding
    @encoded.data
  end

  def parse_init
    # allow the user to specify a section, falls back to .text if none specified
    if not defined? @cursource or not @cursource
      @cursource = Object.new
      class << @cursource
        attr_accessor :elf
        def <<(*a)
          t = Preprocessor::Token.new(nil)
          t.raw = '.text'
          elf.parse_parser_instruction t
          elf.cursource.send(:<<, *a)
        end
      end
      @cursource.elf = self
    end

    @segments.delete_if { |s| s.type == 'INTERP' }
    seg = Segment.new
    seg.type = 'INTERP'
    seg.encoded = EncodedData.new << (@bitsize == 64 ? DEFAULT_INTERP64 : DEFAULT_INTERP) << 0
    seg.flags = ['R']
    seg.memsz = seg.filesz = seg.encoded.length
    @segments.unshift seg

    @source ||= {}
    super()
  end

  # handles elf meta-instructions
  #
  # syntax:
  #   .section "<name>" [<perms>] [base=<base>]
  #     change current section (where normal instruction/data are put)
  #     perms = list of 'w' 'x' 'alloc', may be prefixed by 'no'
  #       'r' ignored
  #       defaults to 'alloc'
  #     shortcuts: .text .data .rodata .bss
  #     base: immediate expression representing the section base address
  #   .entrypoint [<label>]
  #     defines the program entrypoint to the specified label / current location
  #   .global "<name>" [<label>] [<label_end>] [type=<FUNC|OBJECT|...>] [plt=<plt_label_name>] [undef]
  #   .weak   ...
  #   .local  ...
  #     builds a symbol with specified type/scope/size, type defaults to 'func'
  #     if plt_label_name is specified, the compiler will build an entry in the plt for this symbol, with this label (PIC & on-demand resolution)
  #     XXX plt ignored (automagic)
  #   .symbol [global|weak|local] "<name>" ...   see .global/.weak/.local
  #   .needed "<libpath>"
  #     marks the elf as requiring the specified library (DT_NEEDED)
  #   .soname "<soname>"
  #     defines the current elf DT_SONAME (exported library name)
  #   .interp "<interpreter_path>"
  #   .nointerp
  #     defines the required ELF interpreter
  #     defaults to '/lib/ld.so'
  #     'nil'/'none' remove the interpreter specification
  #   .pt_gnu_stack rw|rwx
  #     defines the PT_GNU_STACK flag (default: unspecified, => rwx)
  #   .init/.fini [<label>]
  #     defines the DT_INIT/DT_FINI dynamic tags, same semantic as .entrypoint
  #   .init_array/.fini_array/.preinit_array <label> [, <label>]*
  #     append to the DT_*_ARRAYs
  #
  def parse_parser_instruction(instr)
    readstr = lambda {
      @lexer.skip_space
      t = nil
      raise instr, "string expected, found #{t.raw.inspect if t}" if not t = @lexer.readtok or (t.type != :string and t.type != :quoted)
      t.value || t.raw
    }
    check_eol = lambda {
      @lexer.skip_space
      t = nil
      raise instr, "eol expected, found #{t.raw.inspect if t}" if t = @lexer.nexttok and t.type != :eol
    }

    case instr.raw.downcase
    when '.text', '.data', '.rodata', '.bss'
      sname = instr.raw.downcase
      if not @sections.find { |s| s.name == sname }
        s = Section.new
        s.name = sname
        s.type = 'PROGBITS'
        s.encoded = EncodedData.new
        s.flags = case sname
          when '.text'; %w[ALLOC EXECINSTR]
          when '.data', '.bss'; %w[ALLOC WRITE]
          when '.rodata'; %w[ALLOC]
          end
        s.addralign = 8
        encode_add_section s
      end
      @cursource = @source[sname] ||= []
      check_eol[] if instr.backtrace  # special case for magic @cursource

    when '.section'
      # .section <section name|"section name"> [(no)wxalloc] [base=<expr>]
      sname = readstr[]
      if not s = @sections.find { |s_| s_.name == sname }
        s = Section.new
        s.type = 'PROGBITS'
        s.name = sname
        s.encoded = EncodedData.new
        s.flags = ['ALLOC']
        @sections << s
      end
      loop do
        @lexer.skip_space
        break if not tok = @lexer.nexttok or tok.type != :string
        case @lexer.readtok.raw.downcase
        when /^(no)?r?(w)?(x)?(alloc)?$/
          ar = []
          ar << 'WRITE' if $2
          ar << 'EXECINSTR' if $3
          ar << 'ALLOC' if $4
          if $1; s.flags -= ar
          else   s.flags |= ar
          end
        when 'base'
          @lexer.skip_space
          @lexer.readtok if tok = @lexer.nexttok and tok.type == :punct and tok.raw == '='
          raise instr, 'bad section base' if not s.addr = Expression.parse(@lexer).reduce or not s.addr.kind_of? ::Integer
        else raise instr, 'unknown specifier'
        end
      end
      @cursource = @source[sname] ||= []
      check_eol[]

    when '.entrypoint'
      # ".entrypoint <somelabel/expression>" or ".entrypoint" (here)
      @lexer.skip_space
      if tok = @lexer.nexttok and tok.type == :string
        raise instr if not entrypoint = Expression.parse(@lexer)
      else
        entrypoint = new_label('entrypoint')
        @cursource << Label.new(entrypoint, instr.backtrace.dup)
      end
      @header.entry = entrypoint
      check_eol[]

    when '.global', '.weak', '.local', '.symbol'
      if instr.raw == '.symbol'
        bind = readstr[]
      else
        bind = instr.raw[1..-1]
      end

      s = Symbol.new
      s.name = readstr[]
      s.type = 'FUNC'
      s.bind = bind.upcase
      # define s.section ? should check the section exporting s.target, but it may not be defined now

      # parse pseudo instruction arguments
      loop do
        @lexer.skip_space
        ntok = @lexer.readtok
        if not ntok or ntok.type == :eol
          @lexer.unreadtok ntok
          break
        end
        raise instr, "syntax error: string expected, found #{ntok.raw.inspect}" if ntok.type != :string
        case ntok.raw
        when 'undef'
          s.shndx = 'UNDEF'
        when 'plt'
          @lexer.skip_space
          ntok = @lexer.readtok
          raise "syntax error: = expected, found #{ntok.raw.inspect if ntok}" if not ntok or ntok.type != :punct or ntok.raw != '='
          @lexer.skip_space
          ntok = @lexer.readtok
          raise "syntax error: label expected, found #{ntok.raw.inspect if ntok}" if not ntok or ntok.type != :string
          s.thunk = ntok.raw
        when 'type'
          @lexer.skip_space
          ntok = @lexer.readtok
          raise "syntax error: = expected, found #{ntok.raw.inspect if ntok}" if not ntok or ntok.type != :punct or ntok.raw != '='
          @lexer.skip_space
          ntok = @lexer.readtok
          raise "syntax error: symbol type expected, found #{ntok.raw.inspect if ntok}" if not ntok or ntok.type != :string or not SYMBOL_TYPE.index(ntok.raw)
          s.type = ntok.raw
        when 'size'
          @lexer.skip_space
          ntok = @lexer.readtok
          raise "syntax error: = expected, found #{ntok.raw.inspect if ntok}" if not ntok or ntok.type != :punct or ntok.raw != '='
          @lexer.skip_space
          ntok = @lexer.readtok
          raise "syntax error: symbol size expected, found #{ntok.raw.inspect if ntok}" if not ntok or ntok.type != :string or not ntok.raw =~ /^\d+$/
          s.size = ntok.raw.to_i
        else
          if not s.value
            s.value = ntok.raw
          elsif not s.size
            s.size = Expression[ntok.raw, :-, s.value]
          else
            raise instr, "syntax error: eol expected, found #{ntok.raw.inspect}"
          end
        end
      end
      s.value ||= s.name if not s.shndx and not s.thunk
      s.shndx ||= 1 if s.value
      @symbols << s

    when '.needed'
      # a required library
      (@tag['NEEDED'] ||= []) << readstr[]
      check_eol[]

    when '.soname'
      # exported library name
      @tag['SONAME'] = readstr[]
      check_eol[]
      @segments.delete_if { |s_| s_.type == 'INTERP' }
      @header.type = 'DYN'

    when '.interp', '.nointerp'
      # required ELF interpreter
      interp = ((instr.raw == '.nointerp') ? 'nil' : readstr[])

      @segments.delete_if { |s_| s_.type == 'INTERP' }
      case interp.downcase
      when 'nil', 'no', 'none'
        @header.shnum = 0
      else
        seg = Segment.new
        seg.type = 'INTERP'
        seg.encoded = EncodedData.new << interp << 0
        seg.flags = ['R']
        seg.memsz = seg.filesz = seg.encoded.length
        @segments.unshift seg
      end

      check_eol[]

    when '.pt_gnu_stack'
      # PT_GNU_STACK marking
      mode = readstr[]

      @segments.delete_if { |s_| s_.type == 'GNU_STACK' }
      s = Segment.new
      s.type = 'GNU_STACK'
      case mode
      when /^rw$/i; s.flags = %w[R W]
      when /^rwx$/i; s.flags = %w[R W X]
      else raise instr, "syntax error: expected rw|rwx, found #{mode.inspect}"
      end
      @segments << s

    when '.init', '.fini'
      # dynamic tag initialization
      @lexer.skip_space
      if tok = @lexer.nexttok and tok.type == :string
        raise instr, 'syntax error' if not init = Expression.parse(@lexer)
      else
        init = new_label(instr.raw[1..-1])
        @cursource << Label.new(init, instr.backtrace.dup)
      end
      @tag[instr.raw[1..-1].upcase] = init
      check_eol[]

    when '.init_array', '.fini_array', '.preinit_array'
      t = @tag[instr.raw[1..-1].upcase] ||= []
      loop do
        raise instr, 'syntax error' if not e = Expression.parse(@lexer)
        t << e
        @lexer.skip_space
        ntok = @lexer.nexttok
        break if not ntok or ntok.type == :eol
        raise instr, "syntax error, ',' expected, found #{ntok.raw.inspect}" if nttok != :punct or ntok.raw != ','
        @lexer.readtok
      end

    else super(instr)
    end
  end

  # assembles the hash self.source to a section array
  def assemble(*a)
    parse(*a) if not a.empty?
    @source.each { |k, v|
      raise "no section named #{k} ?" if not s = @sections.find { |s_| s_.name == k }
      s.encoded << assemble_sequence(v, @cpu)
      v.clear
    }
  end

  def encode_file(path, *a)
    ret = super(path, *a)
    File.chmod(0755, path) if @header.entry and @header.entry != 0
    ret
  end

  # defines __ELF__
  def tune_prepro(l)
    l.define_weak('__ELF__', 1)
  end

  # set the data model
  def tune_cparser(cp)
    super(cp)
    cp.lp64 if @cpu.size == 64
  end

  # handles C attributes: export, export_as(foo), import, import_from(libc.so.6), init, fini, entrypoint
  def read_c_attrs(cp)
    cp.toplevel.symbol.each_value { |v|
      next if not v.kind_of? C::Variable
      if v.has_attribute 'export' or ea = v.has_attribute_var('export_as')
        s = Symbol.new
        s.name = ea || v.name
        s.type = v.type.kind_of?(C::Function) ? 'FUNC' : 'NOTYPE'
        s.bind = 'GLOBAL'
        s.shndx = 1
        s.value = v.name
        @symbols << s
      end
      if v.has_attribute 'import' or ln = v.has_attribute_var('import_from')
        (@tag['NEEDED'] ||= []) << ln if ln and not @tag['NEEDED'].to_a.include? ln
        s = Symbol.new
        s.name = v.name
        s.type = v.type.kind_of?(C::Function) ? 'FUNC' : 'NOTYPE'
        s.bind = 'GLOBAL'
        s.shndx = 'UNDEF'
        @symbols << s
      end
      if v.has_attribute('init') or v.has_attribute('constructor')
        (@tag['INIT_ARRAY'] ||= []) << v.name
      end
      if v.has_attribute('fini') or v.has_attribute('destructor')
        (@tag['FINI_ARRAY'] ||= []) << v.name
      end
      if v.has_attribute 'entrypoint'
        @header.entry = v.name
      end
    }
  end

  def c_set_default_entrypoint
    return if @header.entry
    if @sections.find { |s| s.encoded and s.encoded.export['_start'] }
      @header.entry = '_start'
    elsif @sections.find { |s| s.encoded and s.encoded.export['main'] }
      # entrypoint stack: [sp] = argc, [sp+1] = argv0, [sp+2] = argv1, [sp+argc+1] = 0, [sp+argc+2] = envp0, etc
      case @cpu.shortname
      when 'ia32'; assemble <<EOS
_start:
mov eax, [esp]
lea ecx, [esp+4+4*eax+4]
push ecx
lea ecx, [esp+4+4]
push ecx
push eax
call main
push eax
call _exit
EOS
      when 'x64'; assemble <<EOS
_start:
mov rdi, [rsp]
lea rsi, [rsp+8]
lea rdx, [rsi+8*rdi+8]
call main
mov rdi, rax
call _exit
EOS
      else compile_c <<EOS
void _exit(int);
int main(int, char**, char**);
void _start(void) {
  _exit(main(0, 0, 0));
}
EOS
      end
      @header.entry = '_start'
    end
  end
end
end

__END__
elf.assemble Ia32.new, <<EOS
.text				; @sections << Section.new('.text', ['r' 'x'])
.global "foo" foo foo_end	; @symbols ||= [0] << Symbol.new(global, '.foo', addr=foo, size=foo_end - foo)
.global "bla" plt=bla_plt
.needed 'libc.so.6'		; @tag['NEEDED'] ||= [] << 'libc.so.6'
.soname 'lolol'			; @tag['SONAME'] = 'lolol'
.interp nil			; @segments.delete_if { |s| s.type == 'INTERP' } ; @sections.delete_if { |s| s.name == '.interp' && vaddr = seg.vaddr etc }

foo:
  inc eax
  call bla_plt
  ret
foo_end:
EOS
