#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/encode'
require 'metasm/exe_format/coff' unless defined? Metasm::COFF

module Metasm
class COFF
  class OptionalHeader
    # encodes an Optional header and the directories
    def encode(coff)
      opth = super(coff)

      DIRECTORIES[0, @numrva].each { |d|
        if d = coff.directory[d]
          d = d.dup
          d[0] = Expression[d[0], :-, coff.label_at(coff.encoded, 0)] if d[0].kind_of?(::String)
        else
          d = [0, 0]
        end
        opth << coff.encode_word(d[0]) << coff.encode_word(d[1])
      }

      opth
    end

    # find good default values for optheader members, based on coff.sections
    def set_default_values(coff)
      @signature    ||= (coff.bitsize == 64 ? 'PE+' : 'PE')
      @link_ver_maj ||= 1
      @link_ver_min ||= 0
      @sect_align   ||= 0x1000
      align = lambda { |sz| EncodedData.align_size(sz, @sect_align) }
      @code_size    ||= coff.sections.find_all { |s| s.characteristics.include? 'CONTAINS_CODE' }.inject(0) { |sum, s| sum + align[s.virtsize] }
      @data_size    ||= coff.sections.find_all { |s| s.characteristics.include? 'CONTAINS_DATA' }.inject(0) { |sum, s| sum + align[s.virtsize] }
      @udata_size   ||= coff.sections.find_all { |s| s.characteristics.include? 'CONTAINS_UDATA' }.inject(0) { |sum, s| sum + align[s.virtsize] }
      @entrypoint = Expression[@entrypoint, :-, coff.label_at(coff.encoded, 0)] if entrypoint and not @entrypoint.kind_of?(::Integer)
      tmp = coff.sections.find { |s| s.characteristics.include? 'CONTAINS_CODE' }
      @base_of_code ||= (tmp ? Expression[coff.label_at(tmp.encoded, 0), :-, coff.label_at(coff.encoded, 0)] : 0)
      tmp = coff.sections.find { |s| s.characteristics.include? 'CONTAINS_DATA' }
      @base_of_data ||= (tmp ? Expression[coff.label_at(tmp.encoded, 0), :-, coff.label_at(coff.encoded, 0)] : 0)
      @file_align   ||= 0x200
      @os_ver_maj   ||= 4
      @subsys_maj   ||= 4
      @stack_reserve||= 0x100000
      @stack_commit ||= 0x1000
      @heap_reserve ||= 0x100000
      @heap_commit  ||= 0x1000
      @numrva       ||= DIRECTORIES.length

      super(coff)
    end
  end

  class Section
    # find good default values for section header members, defines rawaddr/rawsize as new_label for later fixup
    def set_default_values(coff)
      @name     ||= ''
      @virtsize ||= @encoded.virtsize
      @virtaddr ||= Expression[coff.label_at(@encoded, 0, 'sect_start'), :-, coff.label_at(coff.encoded, 0)]
      @rawsize  ||= coff.new_label('sect_rawsize')
      @rawaddr  ||= coff.new_label('sect_rawaddr')

      super(coff)
    end
  end

  class ExportDirectory
    # encodes an export directory
    def encode(coff)
      edata = {}
      %w[edata addrtable namptable ord_table libname nametable].each { |name|
        edata[name] = EncodedData.new
      }
      label = lambda { |n| coff.label_at(edata[n], 0, n) }
      rva = lambda { |n| Expression[label[n], :-, coff.label_at(coff.encoded, 0)] }
      rva_end = lambda { |n| Expression[[label[n], :-, coff.label_at(coff.encoded, 0)], :+, edata[n].virtsize] }

      # ordinal base: smallest number > 1 to honor ordinals, minimize gaps
      olist = @exports.map { |e| e.ordinal }.compact
      # start with lowest ordinal, substract all exports unused to fill ordinal sequence gaps
      omin = olist.min.to_i
      gaps = olist.empty? ? 0 : olist.max+1 - olist.min - olist.length
      noord = @exports.length - olist.length
      @ordinal_base ||= [omin - (noord - gaps), 1].max

      @libname_p = rva['libname']
      @num_exports = [@exports.length, @exports.map { |e| e.ordinal }.compact.max.to_i - @ordinal_base].max
      @num_names = @exports.find_all { |e| e.name }.length
      @func_p = rva['addrtable']
      @names_p = rva['namptable']
      @ord_p = rva['ord_table']

      edata['edata'] << super(coff)

      edata['libname'] << @libname << 0

      elist = @exports.find_all { |e| e.name and not e.ordinal }.sort_by { |e| e.name }
      @exports.find_all { |e| e.ordinal }.sort_by { |e| e.ordinal }.each { |e| elist.insert(e.ordinal-@ordinal_base, e) }
      elist.each { |e|
        if not e
          # export by ordinal with gaps
          # XXX test this value with the windows loader
          edata['addrtable'] << coff.encode_word(0xffff_ffff)
          next
        end
        if e.forwarder_lib
          edata['addrtable'] << coff.encode_word(rva_end['nametable'])
          edata['nametable'] << e.forwarder_lib << ?. <<
          if not e.forwarder_name
            "##{e.forwarder_ordinal}"
          else
            e.forwarder_name
          end << 0
        else
          edata['addrtable'] << coff.encode_word(Expression[e.target, :-, coff.label_at(coff.encoded, 0)])
        end
        if e.name
          edata['ord_table'] << coff.encode_half(edata['addrtable'].virtsize/4 - 1)
          edata['namptable'] << coff.encode_word(rva_end['nametable'])
          edata['nametable'] << e.name << 0
        end
      }

      # sorted by alignment directives
      %w[edata addrtable namptable ord_table libname nametable].inject(EncodedData.new) { |ed, name| ed << edata[name] }
    end

    def set_default_values(coff)
      @timestamp ||= Time.now.to_i
      @libname ||= 'metalib'
      @ordinal_base ||= 1

      super(coff)
    end
  end

  class ImportDirectory
    # encode all import directories + iat
    def self.encode(coff, ary)
      edata = { 'iat' => [] }
      %w[idata ilt nametable].each { |name| edata[name] = EncodedData.new }

      ary.each { |i| i.encode(coff, edata) }

      it = edata['idata'] <<
      coff.encode_word(0) <<
      coff.encode_word(0) <<
      coff.encode_word(0) <<
      coff.encode_word(0) <<
      coff.encode_word(0) <<
      edata['ilt'] <<
      edata['nametable']

      iat = edata['iat']	# why not fragmented ?

      [it, iat]
    end

    # encode one import directory + iat + names in the edata hash received as arg
    def encode(coff, edata)
      edata['iat'] << EncodedData.new
      # edata['ilt'] = edata['iat']
      label = lambda { |n| coff.label_at(edata[n], 0, n) }
      rva_end = lambda { |n| Expression[[label[n], :-, coff.label_at(coff.encoded, 0)], :+, edata[n].virtsize] }

      @libname_p = rva_end['nametable']
      @ilt_p = rva_end['ilt']
      @iat_p ||= Expression[coff.label_at(edata['iat'].last, 0, 'iat'), :-, coff.label_at(coff.encoded, 0)]
      edata['idata'] << super(coff)

      edata['nametable'] << @libname << 0

      ord_mask = 1 << (coff.bitsize - 1)
      @imports.each { |i|
        edata['iat'].last.add_export i.target, edata['iat'].last.virtsize if i.target
        if i.ordinal
          ptr = coff.encode_xword(Expression[i.ordinal, :|, ord_mask])
        else
          edata['nametable'].align 2
          ptr = coff.encode_xword(rva_end['nametable'])
          edata['nametable'] << coff.encode_half(i.hint || 0) << i.name << 0
        end
        edata['ilt'] << ptr
        edata['iat'].last << ptr
      }
      edata['ilt'] << coff.encode_xword(0)
      edata['iat'].last << coff.encode_xword(0)
    end
  end

  class TLSDirectory
    def encode(coff)
      cblist = EncodedData.new
      @callback_p = coff.label_at(cblist, 0, 'callback_p')
      @callbacks.to_a.each { |cb|
        cblist << coff.encode_xword(cb)
      }
      cblist << coff.encode_xword(0)

      dir = super(coff)

      [dir, cblist]
    end

    def set_default_values(coff)
      @start_va ||= 0
      @end_va ||= @start_va

      super(coff)
    end
  end

  class RelocationTable
    # encodes a COFF relocation table
    def encode(coff)
      rel = super(coff) << coff.encode_word(8 + 2*@relocs.length)
      @relocs.each { |r| rel << r.encode(coff) }
      rel
    end

    def set_default_values(coff)
      # @base_addr is an rva
      @base_addr = Expression[@base_addr, :-, coff.label_at(coff.encoded, 0)] if @base_addr.kind_of?(::String)

      # align relocation table size
      if @relocs.length % 2 != 0
        r = Relocation.new
        r.type = 0
        r.offset = 0
        @relocs << r
      end

      super(coff)
    end
  end

  class ResourceDirectory
    # compiles ressource directories
    def encode(coff, edata = nil)
      if not edata
        # init recursion
        edata = {}
        subtables = %w[table names dataentries data]
        subtables.each { |n| edata[n] = EncodedData.new }
        encode(coff, edata)
        return subtables.inject(EncodedData.new) { |sum, n| sum << edata[n] }
      end

      label = lambda { |n| coff.label_at(edata[n], 0, n) }
      # data 'rva' are real rvas (from start of COFF)
      rva_end = lambda { |n| Expression[[label[n], :-, coff.label_at(coff.encoded, 0)], :+, edata[n].virtsize] }
      # names and table 'rva' are relative to the beginning of the resource directory
      off_end = lambda { |n| Expression[[label[n], :-, coff.label_at(edata['table'], 0)], :+, edata[n].virtsize] }

      # build name_w if needed
      @entries.each { |e| e.name_w = e.name.unpack('C*').pack('v*') if e.name and not e.name_w }

      # fixup forward references to us, as subdir
      edata['table'].fixup @curoff_label => edata['table'].virtsize if defined? @curoff_label

      @nr_names = @entries.find_all { |e| e.name_w }.length
      @nr_id = @entries.find_all { |e| e.id }.length
      edata['table'] << super(coff)

      # encode entries, sorted by names nocase, then id
      @entries.sort_by { |e| e.name_w ? [0, e.name_w.downcase] : [1, e.id] }.each { |e|
        if e.name_w
          edata['table'] << coff.encode_word(Expression[off_end['names'], :|, 1 << 31])
          edata['names'] << coff.encode_half(e.name_w.length/2) << e.name_w
        else
          edata['table'] << coff.encode_word(e.id)
        end

        if e.subdir
          e.subdir.curoff_label = coff.new_label('rsrc_curoff')
          edata['table'] << coff.encode_word(Expression[e.subdir.curoff_label, :|, 1 << 31])
        else # data entry
          edata['table'] << coff.encode_word(off_end['dataentries'])

          edata['dataentries'] <<
          coff.encode_word(rva_end['data']) <<
          coff.encode_word(e.data.length) <<
          coff.encode_word(e.codepage || 0) <<
          coff.encode_word(e.reserved || 0)

          edata['data'] << e.data
        end
      }

      # recurse
      @entries.find_all { |e| e.subdir }.each { |e| e.subdir.encode(coff, edata) }
    end
  end


  # computes the checksum for a given COFF file
  # may not work with overlapping sections
  def self.checksum(str, endianness = :little)
    coff = load str
    coff.endianness = endianness
    coff.decode_header
    coff.encoded.ptr = 0

    flen = 0
    csum = 0
    # negate old checksum
    oldcs = coff.encode_word(coff.optheader.checksum)
    oldcs.ptr = 0
    csum -= coff.decode_half(oldcs)
    csum -= coff.decode_half(oldcs)

    # checksum header
    raw = coff.encoded.read(coff.optheader.headers_size)
    flen += coff.optheader.headers_size

    coff.sections.each { |s|
      coff.encoded.ptr = s.rawaddr
      raw << coff.encoded.read(s.rawsize)
      flen += s.rawsize
    }
    raw.unpack(endianness == :little ? 'v*' : 'n*').each { |s|
      csum += s
      csum = (csum & 0xffff) + (csum >> 16) if (csum >> 16) > 0
    }
    csum + flen
  end


  def encode_byte(w)   Expression[w].encode(:u8,  @endianness, (caller if $DEBUG)) end
  def encode_half(w)   Expression[w].encode(:u16, @endianness, (caller if $DEBUG)) end
  def encode_word(w)   Expression[w].encode(:u32, @endianness, (caller if $DEBUG)) end
  def encode_xword(w)  Expression[w].encode((@bitsize == 32 ? :u32 : :u64), @endianness, (caller if $DEBUG)) end


  # adds a new compiler-generated section
  def encode_append_section(s)
    if (s.virtsize || s.encoded.virtsize) < 4096
      # find section to merge with
      # XXX check following sections for hardcoded base address ?

      char = s.characteristics.dup
      secs = @sections.dup
      # do not merge non-discardable in discardable
      if not char.delete 'MEM_DISCARDABLE'
        secs.delete_if { |ss| ss.characteristics.include? 'MEM_DISCARDABLE' }
      end
      # do not merge shared w/ non-shared
      if char.delete 'MEM_SHARED'
        secs.delete_if { |ss| not ss.characteristics.include? 'MEM_SHARED' }
      else
        secs.delete_if { |ss| ss.characteristics.include? 'MEM_SHARED' }
      end
      secs.delete_if { |ss| ss.virtsize.kind_of?(::Integer) or ss.rawsize.kind_of?(::Integer) or secs[secs.index(ss)+1..-1].find { |ss_| ss_.virtaddr.kind_of?(::Integer) } }

      # try to find superset of characteristics
      if target = secs.find { |ss| (ss.characteristics & char) == char }
        target.encoded.align 8
        puts "PE: merging #{s.name} in #{target.name} (#{target.encoded.virtsize})" if $DEBUG
        s.encoded = target.encoded << s.encoded
      else
        @sections << s
      end
    else
      @sections << s
    end
  end

  # encodes the export table as a new section, updates directory['export_table']
  def encode_exports
    edata = @export.encode self

    # must include name tables (for forwarders)
    @directory['export_table'] = [label_at(edata, 0, 'export_table'), edata.virtsize]

    s = Section.new
    s.name = '.edata'
    s.encoded = edata
    s.characteristics = %w[MEM_READ]
    encode_append_section s
  end

  # encodes the import tables as a new section, updates directory['import_table'] and directory['iat']
  def encode_imports
    idata, iat = ImportDirectory.encode(self, @imports)

    @directory['import_table'] = [label_at(idata, 0, 'idata'), idata.virtsize]

    s = Section.new
    s.name = '.idata'
    s.encoded = idata
    s.characteristics = %w[MEM_READ MEM_WRITE MEM_DISCARDABLE]
    encode_append_section s

    if @imports.first and @imports.first.iat_p.kind_of?(Integer)
      # ordiat = iat.sort_by { @import[x].iat_p }
      ordiat = @imports.zip(iat).sort_by { |id, it| id.iat_p.kind_of?(Integer) ? id.iat_p : 1<<65 }.map { |id, it| it }
    else
      ordiat = iat
    end

    @directory['iat'] = [label_at(ordiat.first, 0, 'iat'),
      Expression[label_at(ordiat.last, ordiat.last.virtsize, 'iat_end'), :-, label_at(ordiat.first, 0)]] if not ordiat.empty?

    iat_s = nil

    plt = Section.new
    plt.name = '.plt'
    plt.encoded = EncodedData.new
    plt.characteristics = %w[MEM_READ MEM_EXECUTE]

    @imports.zip(iat) { |id, it|
      if id.iat_p.kind_of?(Integer) and @sections.find { |s_| s_.virtaddr <= id.iat_p and s_.virtaddr + (s_.virtsize || s_.encoded.virtsize) > id.iat_p }
        id.iat = it	# will be fixed up after encode_section
      else
        # XXX should not be mixed (for @directory['iat'][1])
        if not iat_s
          iat_s = Section.new
          iat_s.name = '.iat'
          iat_s.encoded = EncodedData.new
          iat_s.characteristics = %w[MEM_READ MEM_WRITE]
          encode_append_section iat_s
        end
        iat_s.encoded << it
      end

      id.imports.each { |i|
        if i.thunk
          arch_encode_thunk(plt.encoded, i)
        end
      }
    }

    encode_append_section plt if not plt.encoded.empty?
  end

  # encodes a thunk to imported function
  def arch_encode_thunk(edata, import)
    case @cpu.shortname
    when 'ia32', 'x64'
      shellcode = lambda { |c| Shellcode.new(@cpu).share_namespace(self).assemble(c).encoded }
      if @cpu.generate_PIC
        if @cpu.shortname == 'x64'
          edata << shellcode["#{import.thunk}: jmp [rip-$_+#{import.target}]"]
          return
        end
        # sections starts with a helper function that returns the address of metasm_intern_geteip in eax (PIC)
        if not @sections.find { |s| s.encoded and s.encoded.export['metasm_intern_geteip'] } and edata.empty?
          edata << shellcode["metasm_intern_geteip: call 42f\n42:\npop eax\nsub eax, 42b-metasm_intern_geteip\nret"]
        end
        edata << shellcode["#{import.thunk}: call metasm_intern_geteip\njmp [eax+#{import.target}-metasm_intern_geteip]"]
      else
        edata << shellcode["#{import.thunk}: jmp [#{import.target}]"]
      end
    else raise EncodeError, 'E: COFF: encode import thunk: unsupported architecture'
    end
  end

  def encode_tls
    dir, cbtable = @tls.encode(self)
    @directory['tls_table'] = [label_at(dir, 0, 'tls_table'), dir.virtsize]

    s = Section.new
    s.name = '.tls'
    s.encoded = EncodedData.new << dir << cbtable
    s.characteristics = %w[MEM_READ MEM_WRITE]
    encode_append_section s
  end

  # encodes relocation tables in a new section .reloc, updates @directory['base_relocation_table']
  def encode_relocs
    if @relocations.empty?
      rt = RelocationTable.new
      rt.base_addr = 0
      rt.relocs = []
      @relocations << rt
    end
    relocs = @relocations.inject(EncodedData.new) { |edata, rt_| edata << rt_.encode(self) }

    @directory['base_relocation_table'] = [label_at(relocs, 0, 'reloc_table'), relocs.virtsize]

    s = Section.new
    s.name = '.reloc'
    s.encoded = relocs
    s.characteristics = %w[MEM_READ MEM_DISCARDABLE]
    encode_append_section s
  end

  # creates the @relocations from sections.encoded.reloc
  def create_relocation_tables
    @relocations = []

    # create a fake binding with all exports, to find only-image_base-dependant relocs targets
    # not foolproof, but works in standard cases
    startaddr = curaddr = label_at(@encoded, 0, 'coff_start')
    binding = {}
    @sections.each { |s|
      binding.update s.encoded.binding(curaddr)
      curaddr = Expression[curaddr, :+, s.encoded.virtsize]
    }

    # for each section.encoded, make as many RelocationTables as needed
    @sections.each { |s|

      # rt.base_addr temporarily holds the offset from section_start, and is fixed up to rva before '@reloc << rt'
      rt = RelocationTable.new

      s.encoded.reloc.each { |off, rel|
        # check that the relocation looks like "program_start + integer" when bound using the fake binding
        # XXX allow :i32 etc
        if rel.endianness == @endianness and [:u32, :a32, :u64, :a64].include?(rel.type) and
        rel.target.bind(binding).reduce.kind_of?(Expression) and
        Expression[rel.target, :-, startaddr].bind(binding).reduce.kind_of?(::Integer)
          # winner !

          # build relocation
          r = RelocationTable::Relocation.new
          r.offset = off & 0xfff
          r.type = { :u32 => 'HIGHLOW', :u64 => 'DIR64', :a32 => 'HIGHLOW', :a64 => 'DIR64' }[rel.type]

          # check if we need to start a new relocation table
          if rt.base_addr and (rt.base_addr & ~0xfff) != (off & ~0xfff)
            rt.base_addr = Expression[[label_at(s.encoded, 0, 'sect_start'), :-, startaddr], :+, rt.base_addr]
            @relocations << rt
            rt = RelocationTable.new
          end

          # initialize reloc table base address if needed
          rt.base_addr ||= off & ~0xfff

          (rt.relocs ||= []) << r
        elsif $DEBUG and not rel.target.bind(binding).reduce.kind_of?(Integer)
          puts "W: COFF: Ignoring weird relocation #{rel.inspect} when building relocation tables"
        end
      }

      if rt and rt.relocs
        rt.base_addr = Expression[[label_at(s.encoded, 0, 'sect_start'), :-, startaddr], :+, rt.base_addr]
        @relocations << rt
      end
    }
  end

  def encode_resource
    res = @resource.encode self

    @directory['resource_table'] = [label_at(res, 0, 'resource_table'), res.virtsize]

    s = Section.new
    s.name = '.rsrc'
    s.encoded = res
    s.characteristics = %w[MEM_READ]
    encode_append_section s
  end

  # initialize the header from target/cpu/etc, target in ['exe' 'dll' 'kmod' 'obj']
  def pre_encode_header(target='exe', want_relocs=true)
    target = {:bin => 'exe', :lib => 'dll', :obj => 'obj', 'sys' => 'kmod', 'drv' => 'kmod'}.fetch(target, target)

    @header.machine ||= case @cpu.shortname
        when 'x64'; 'AMD64'
        when 'ia32'; 'I386'
        end
    @optheader.signature ||= case @cpu.size
        when 32; 'PE'
        when 64; 'PE+'
        end
    @bitsize = (@optheader.signature == 'PE+' ? 64 : 32)

    # setup header flags
    tmp = %w[LINE_NUMS_STRIPPED LOCAL_SYMS_STRIPPED DEBUG_STRIPPED] +
      case target
      when 'exe';  %w[EXECUTABLE_IMAGE]
      when 'dll';  %w[EXECUTABLE_IMAGE DLL]
      when 'kmod'; %w[EXECUTABLE_IMAGE]
      when 'obj';  []
      end
    if @cpu.size == 32
      tmp << 'x32BIT_MACHINE'
    else
      tmp << 'LARGE_ADDRESS_AWARE'
    end
    tmp << 'RELOCS_STRIPPED' if not want_relocs
    @header.characteristics ||= tmp

    @optheader.subsystem ||= case target
      when 'exe', 'dll'; 'WINDOWS_GUI'
      when 'kmod'; 'NATIVE'
      end

    tmp = []
    tmp << 'NX_COMPAT'
    tmp << 'DYNAMIC_BASE' if want_relocs
    @optheader.dll_characts ||= tmp
  end

  # resets the values in the header that may have been
  # modified by your script (eg section count, size, imagesize, etc)
  # call this whenever you decode a file, modify it, and want to reencode it later
  def invalidate_header
    # set those values to nil, they will be
    # recomputed during encode_header
    [:code_size, :data_size, :udata_size, :base_of_code, :base_of_data,
     :sect_align, :file_align, :image_size, :headers_size, :checksum].each { |m| @optheader.send("#{m}=", nil) }
    [:num_sect, :ptr_sym, :num_sym, :size_opthdr].each { |m| @header.send("#{m}=", nil) }
  end

  # appends the header/optheader/directories/section table to @encoded
  def encode_header
    # encode section table, add CONTAINS_* flags from other characteristics flags
    s_table = EncodedData.new

    @sections.each { |s|
      if s.characteristics.kind_of? Array and s.characteristics.include? 'MEM_READ'
        if s.characteristics.include? 'MEM_EXECUTE'
          s.characteristics |= ['CONTAINS_CODE']
        elsif s.encoded
          if s.encoded.rawsize == 0
            s.characteristics |= ['CONTAINS_UDATA']
          else
            s.characteristics |= ['CONTAINS_DATA']
          end
        end
      end
      s.rawaddr = nil if s.rawaddr.kind_of?(::Integer)	# XXX allow to force rawaddr ?
      s_table << s.encode(self)
    }

    # encode optional header
    @optheader.image_size   ||= new_label('image_size')
    @optheader.image_base   ||= label_at(@encoded, 0)
    @optheader.headers_size ||= new_label('headers_size')
    @optheader.checksum     ||= new_label('checksum')
    @optheader.subsystem    ||= 'WINDOWS_GUI'
    @optheader.numrva = nil
    opth = @optheader.encode(self)

    # encode header
    @header.machine ||= 'UNKNOWN'
    @header.num_sect ||= sections.length
    @header.time ||= Time.now.to_i & -255
    @header.size_opthdr ||= opth.virtsize
    @encoded << @header.encode(self) << opth << s_table
  end

  # append the section bodies to @encoded, and link the resulting binary
  def encode_sections_fixup
    if @optheader.headers_size.kind_of?(::String)
      @encoded.fixup! @optheader.headers_size => @encoded.virtsize
      @optheader.headers_size = @encoded.virtsize
    end
    @encoded.align @optheader.file_align

    baseaddr = @optheader.image_base.kind_of?(::Integer) ? @optheader.image_base : 0x400000
    binding = @encoded.binding(baseaddr)

    curaddr = baseaddr + @optheader.headers_size
    @sections.each { |s|
      # align
      curaddr = EncodedData.align_size(curaddr, @optheader.sect_align)
      if s.rawaddr.kind_of?(::String)
        @encoded.fixup! s.rawaddr => @encoded.virtsize
        s.rawaddr = @encoded.virtsize
      end
      if s.virtaddr.kind_of?(::Integer)
        raise "E: COFF: cannot encode section #{s.name}: hardcoded address too short" if curaddr > baseaddr + s.virtaddr
        curaddr = baseaddr + s.virtaddr
      end
      binding.update s.encoded.binding(curaddr)
      curaddr += s.virtsize

      pre_sz = @encoded.virtsize
      @encoded << s.encoded[0, s.encoded.rawsize]
      @encoded.align @optheader.file_align
      if s.rawsize.kind_of?(::String)
        @encoded.fixup! s.rawsize => (@encoded.virtsize - pre_sz)
        s.rawsize = @encoded.virtsize - pre_sz
      end
    }

    # not aligned ? spec says it is, visual studio does not
    binding[@optheader.image_size] = curaddr - baseaddr if @optheader.image_size.kind_of?(::String)

    # patch the iat where iat_p was defined
    # sort to ensure a 0-terminated will not overwrite an entry
    # (try to dump notepad.exe, which has a forwarder;)
    @imports.find_all { |id| id.iat_p.kind_of?(Integer) }.sort_by { |id| id.iat_p }.each { |id|
      s = sect_at_rva(id.iat_p)
      @encoded[s.rawaddr + s.encoded.ptr, id.iat.virtsize] = id.iat
      binding.update id.iat.binding(baseaddr + id.iat_p)
    } if imports

    @encoded.fill
    @encoded.fixup! binding

    if @optheader.checksum.kind_of?(::String) and @encoded.reloc.length == 1
      # won't work if there are other unresolved relocs
      checksum = self.class.checksum(@encoded.data, @endianness)
      @encoded.fixup @optheader.checksum => checksum
      @optheader.checksum = checksum
    end
  end

  # encode a COFF file, building export/import/reloc tables if needed
  # creates the base relocation tables (need for references to IAT not known before)
  # defaults to generating relocatable files, eg ALSR-aware
  # pass want_relocs=false to avoid the file overhead induced by this
  def encode(target='exe', want_relocs=true)
    @encoded = EncodedData.new
    label_at(@encoded, 0, 'coff_start')
    pre_encode_header(target, want_relocs)
    autoimport
    encode_exports if export
    encode_imports if imports
    encode_resource if resource
    encode_tls if tls
    create_relocation_tables if want_relocs
    encode_relocs if relocations
    encode_header
    encode_sections_fixup
    @encoded.data
  end

  def parse_init
    # ahem...
    # a fake object, which when appended makes us parse '.text', which creates a real default section
    # forwards to it this first appendage.
    # allows the user to specify its own section if he wishes, and to use .text if he doesn't
    if not defined? @cursource or not @cursource
      @cursource = ::Object.new
      class << @cursource
        attr_accessor :coff
        def <<(*a)
          t = Preprocessor::Token.new(nil)
          t.raw = '.text'
          coff.parse_parser_instruction t
          coff.cursource.send(:<<, *a)
        end
      end
      @cursource.coff = self
    end
    @source ||= {}
    super()
  end

  # handles compiler meta-instructions
  #
  # syntax:
  #  .section "<section name>" <perm list> <base>
  #    section name is a string (may be quoted)
  #    perms are in 'r' 'w' 'x' 'shared' 'discard', may be concatenated (in this order), may be prefixed by 'no' to remove the attribute for an existing section
  #    base is the token 'base', the token '=' and an immediate expression
  #    default sections:
  #    .text =   .section '.text' rx
  #    .data =   .section '.data' rw
  #    .rodata = .section '.rodata' r
  #    .bss =    .section '.bss' rw
  #  .entrypoint | .entrypoint <label>
  #    defines the label as the program entrypoint
  #    without argument, creates a label used as entrypoint
  #  .libname "<name>"
  #    defines the string to be used as exported library name (should be the same as the file name, may omit extension)
  #  .export ["<exported_name>"] [<ordinal>] [<label_name>]
  #    exports the specified label with the specified name (label_name defaults to exported_name)
  #    if exported_name is an unquoted integer, the export is by ordinal. XXX if the ordinal starts with '0', the integer is interpreted as octal
  #  .import "<libname>" "<import_name|ordinal>" [<thunk_name>] [<label_name>]
  #    imports a symbol from a library
  #    if the thunk name is specified and not 'nil', the compiler will generate a thunk that can be called (in ia32, 'call thunk' == 'call [import_name]')
  #      the thunk is position-independent, and should be used instead of the indirect call form, for imported functions
  #    label_name is the label to attribute to the location that will receive the address of the imported symbol, defaults to import_name (iat_<import_name> if thunk == iname)
  #  .image_base <base>
  #    specifies the COFF prefered load address, base is an immediate expression
  #
  def parse_parser_instruction(instr)
    readstr = lambda {
      @lexer.skip_space
      raise instr, 'string expected' if not t = @lexer.readtok or (t.type != :string and t.type != :quoted)
      t.value || t.raw
    }
    check_eol = lambda {
      @lexer.skip_space
      raise instr, 'eol expected' if t = @lexer.nexttok and t.type != :eol
    }
    case instr.raw.downcase
    when '.text', '.data', '.rodata', '.bss'
      sname = instr.raw.downcase
      if not @sections.find { |s| s.name == sname }
        s = Section.new
        s.name = sname
        s.encoded = EncodedData.new
        s.characteristics = case sname
          when '.text'; %w[MEM_READ MEM_EXECUTE]
          when '.data', '.bss'; %w[MEM_READ MEM_WRITE]
          when '.rodata'; %w[MEM_READ]
          end
        @sections << s
      end
      @cursource = @source[sname] ||= []
      check_eol[] if instr.backtrace	# special case for magic @cursource

    when '.section'
      # .section <section name|"section name"> [(no)r w x shared discard] [base=<expr>]
      sname = readstr[]
      if not s = @sections.find { |s_| s_.name == sname }
        s = Section.new
        s.name = sname
        s.encoded = EncodedData.new
        s.characteristics = []
        @sections << s
      end
      loop do
        @lexer.skip_space
        break if not tok = @lexer.nexttok or tok.type != :string
        case @lexer.readtok.raw.downcase
        when /^(no)?(r)?(w)?(x)?(shared)?(discard)?$/
          ar = []
          ar << 'MEM_READ' if $2
          ar << 'MEM_WRITE' if $3
          ar << 'MEM_EXECUTE' if $4
          ar << 'MEM_SHARED' if $5
          ar << 'MEM_DISCARDABLE' if $6
          if $1; s.characteristics -= ar
          else   s.characteristics |= ar
          end
        when 'base'
          @lexer.skip_space
          @lexer.unreadtok tok if not tok = @lexer.readtok or tok.type != :punct or tok.raw != '='
          raise instr, 'invalid base' if not s.virtaddr = Expression.parse(@lexer).reduce or not s.virtaddr.kind_of?(::Integer)
          if not @optheader.image_base
            @optheader.image_base = (s.virtaddr-0x80) & 0xfff00000
            puts "Warning: no image_base specified, using #{Expression[@optheader.image_base]}" if $VERBOSE
          end
          s.virtaddr -= @optheader.image_base
        else raise instr, 'unknown parameter'
        end
      end
      @cursource = @source[sname] ||= []
      check_eol[]

    when '.libname'
      # export directory library name
      # .libname <libname|"libname">
      @export ||= ExportDirectory.new
      @export.libname = readstr[]
      check_eol[]

    when '.export'
      # .export <export name|ordinal|"export name"> [ordinal] [label to export if different]
      @lexer.skip_space
      raise instr, 'string expected' if not tok = @lexer.readtok or (tok.type != :string and tok.type != :quoted)
      exportname = tok.value || tok.raw
      if tok.type == :string and (?0..?9).include? tok.raw[0]
        exportname = Integer(exportname) rescue raise(tok, "bad ordinal value, try quotes #{' or rm leading 0' if exportname[0] == ?0}")
      end

      @lexer.skip_space
      tok = @lexer.readtok
      if tok and tok.type == :string and (?0..?9).include? tok.raw[0]
        (eord = Integer(tok.raw)) rescue @lexer.unreadtok(tok)
      else @lexer.unreadtok(tok)
      end

      @lexer.skip_space
      tok = @lexer.readtok
      if tok and tok.type == :string
        exportlabel = tok.raw
      else
        @lexer.unreadtok tok
      end

      @export ||= ExportDirectory.new
      @export.exports ||= []
      e = ExportDirectory::Export.new
      if exportname.kind_of? Integer
        e.ordinal = exportname
      else
        e.name = exportname
        e.ordinal = eord if eord
      end
      e.target = exportlabel || exportname
      @export.exports << e
      check_eol[]

    when '.import'
      # .import <libname|"libname"> <imported sym|"imported sym"> [label of plt thunk|nil] [label of iat element if != symname]
      libname = readstr[]
      i = ImportDirectory::Import.new

      @lexer.skip_space
      raise instr, 'string expected' if not tok = @lexer.readtok or (tok.type != :string and tok.type != :quoted)
      if tok.type == :string and (?0..?9).include? tok.raw[0]
        i.ordinal = Integer(tok.raw)
      else
        i.name = tok.value || tok.raw
      end

      @lexer.skip_space
      if tok = @lexer.readtok and tok.type == :string
        i.thunk = tok.raw if tok.raw != 'nil'
        @lexer.skip_space
        tok = @lexer.readtok
      end
      if tok and tok.type == :string
        i.target = tok.raw
      else
        i.target = ((i.thunk == i.name) ? ('iat_' + i.name) : (i.name ? i.name : (i.thunk ? 'iat_' + i.thunk : raise(instr, 'need iat label'))))
        @lexer.unreadtok tok
      end
      raise tok, 'import target exists' if i.target != new_label(i.target)

      @imports ||= []
      if not id = @imports.find { |id_| id_.libname == libname }
        id = ImportDirectory.new
        id.libname = libname
        id.imports = []
        @imports << id
      end
      id.imports << i

      check_eol[]

    when '.entrypoint'
      # ".entrypoint <somelabel/expression>" or ".entrypoint" (here)
      @lexer.skip_space
      if tok = @lexer.nexttok and tok.type == :string
        raise instr, 'syntax error' if not entrypoint = Expression.parse(@lexer)
      else
        entrypoint = new_label('entrypoint')
        @cursource << Label.new(entrypoint, instr.backtrace.dup)
      end
      @optheader.entrypoint = entrypoint
      check_eol[]

    when '.image_base'
      raise instr if not base = Expression.parse(@lexer) or !(base = base.reduce).kind_of?(::Integer)
      @optheader.image_base = base
      check_eol[]

    when '.subsystem'
      @lexer.skip_space
      raise instr if not tok = @lexer.readtok
      @optheader.subsystem = tok.raw
      check_eol[]

    else super(instr)
    end
  end

  def assemble(*a)
    parse(*a) if not a.empty?
    @source.each { |k, v|
      raise "no section named #{k} ?" if not s = @sections.find { |s_| s_.name == k }
      s.encoded << assemble_sequence(v, @cpu)
      v.clear
    }
  end

  # defines __PE__
  def tune_prepro(l)
    l.define_weak('__PE__', 1)
    l.define_weak('__MS_X86_64_ABI__') if @cpu and @cpu.shortname == 'x64'
  end

  def tune_cparser(cp)
    super(cp)
    cp.llp64 if @cpu.size == 64
  end

  # honors C attributes: export, export_as(foo), import_from(kernel32), entrypoint
  # import by ordinal: extern __stdcall int anyname(int) __attribute__((import_from(ws2_32:28)));
  # can alias imports with int mygpaddr_alias() attr(import_from(kernel32:GetProcAddr))
  def read_c_attrs(cp)
    cp.toplevel.symbol.each_value { |v|
      next if not v.kind_of? C::Variable
      if v.has_attribute 'export' or ea = v.has_attribute_var('export_as')
        @export ||= ExportDirectory.new
        @export.exports ||= []
        e = ExportDirectory::Export.new
        begin
          e.ordinal = Integer(ea || v.name)
        rescue ArgumentError
          e.name = ea || v.name
        end
        e.target = v.name
        @export.exports << e
      end
      if v.has_attribute('import') or ln = v.has_attribute_var('import_from')
        ln ||= WindowsExports::EXPORT[v.name]
        raise "unknown library for #{v.name}" if not ln
        i = ImportDirectory::Import.new
        if ln.include? ':'
          ln, name = ln.split(':')
          begin
            i.ordinal = Integer(name)
          rescue ArgumentError
            i.name = name
          end
        else
          i.name = v.name
        end
        if v.type.kind_of? C::Function
          i.thunk = v.name
          i.target = 'iat_'+i.thunk
        else
          i.target = v.name
        end

        @imports ||= []
        if not id = @imports.find { |id_| id_.libname == ln }
          id = ImportDirectory.new
          id.libname = ln
          id.imports = []
          @imports << id
        end
        id.imports << i
      end
      if v.has_attribute 'entrypoint'
        @optheader.entrypoint = v.name
      end
    }
  end

  # try to resolve automatically COFF import tables from self.sections.encoded.relocations
  # and WindowsExports::EXPORT
  # if the relocation target is '<symbolname>' or 'iat_<symbolname>, link to the IAT address, if it is '<symbolname> + <expr>',
  # link to a thunk (plt-like)
  # if the relocation is not found, try again after appending 'fallback_append' to the symbol (eg wsprintf => wsprintfA)
  def autoimport(fallback_append='A')
    WindowsExports rescue return	# autorequire
    autoexports = WindowsExports::EXPORT.dup
    @sections.each { |s|
      next if not s.encoded
      s.encoded.export.keys.each { |e| autoexports.delete e }
    }
    @sections.each { |s|
      next if not s.encoded
      s.encoded.reloc.each_value { |r|
        if r.target.op == :+ and not r.target.lexpr and r.target.rexpr.kind_of?(::String)
          sym = target = r.target.rexpr
          sym = sym[4..-1] if sym[0, 4] == 'iat_'
        elsif r.target.op == :- and r.target.rexpr.kind_of?(::String) and r.target.lexpr.kind_of?(::String)
          sym = thunk = r.target.lexpr
        end
        if not dll = autoexports[sym]
          sym += fallback_append if sym.kind_of?(::String) and fallback_append.kind_of?(::String)
          next if not dll = autoexports[sym]
        end

        @imports ||= []
        next if @imports.find { |id| id.imports.find { |ii| ii.name == sym } }
        if not id = @imports.find { |id_| id_.libname =~ /^#{dll}(\.dll)?$/i }
          id = ImportDirectory.new
          id.libname = dll
          id.imports = []
          @imports << id
        end
        if not i = id.imports.find { |i_| i_.name == sym }
          i = ImportDirectory::Import.new
          i.name = sym
          id.imports << i
        end
        if (target and i.target and (i.target != target or i.thunk == target)) or
           (thunk  and i.thunk  and (i.thunk  != thunk or  i.target == thunk))
          puts "autoimport: conflict for #{target} #{thunk} #{i.inspect}" if $VERBOSE
        else
          i.target ||= new_label(target || 'iat_' + thunk)
          i.thunk ||= thunk if thunk
        end
      }
    }
  end
end
end
