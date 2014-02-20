#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/exe_format/main'
require 'metasm/encode'
require 'metasm/decode'

module Metasm
class MachO < ExeFormat
  MAGIC = "\xfe\xed\xfa\xce"	# 0xfeedface
  CIGAM = MAGIC.reverse		# 0xcefaedfe
  MAGIC64 = "\xfe\xed\xfa\xcf"	# 0xfeedfacf
  CIGAM64 = MAGIC64.reverse	# 0xcffaedfe

  MAGICS = [MAGIC, CIGAM, MAGIC64, CIGAM64]

  CPU = {
    1 => 'VAX', 2 => 'ROMP',
    4 => 'NS32032', 5 => 'NS32332',
    6 => 'MC680x0', 7 => 'I386',
    8 => 'MIPS', 9 => 'NS32532',
    11 => 'HPPA', 12 => 'ARM',
    13 => 'MC88000', 14 => 'SPARC',
    15 => 'I860', 16 => 'I860_LITTLE',
    17 => 'RS6000', 18 => 'POWERPC',
    #0x100_0000 => 'CPU_ARCH_ABI64',
    0x100_0000|7  => 'X86_64',
    0x100_0000|18 => 'POWERPC64',
    255 => 'VEO',
    0xffff_ffff => 'ANY',
  }

  SUBCPU = {
    'VAX' => { 0 => 'ALL',
      1 => '780', 2 => '785', 3 => '750', 4 => '730',
      5 => 'UVAXI', 6 => 'UVAXII', 7 => '8200', 8 => '8500',
      9 => '8600', 10 => '8650', 11 => '8800', 12 => 'UVAXIII',
    },
    'ROMP' => { 0 => 'ALL', 1 => 'PC', 2 => 'APC', 3 => '135',
      0 => 'MMAX_ALL', 1 => 'MMAX_DPC', 2 => 'SQT',
      3 => 'MMAX_APC_FPU', 4 => 'MMAX_APC_FPA', 5 => 'MMAX_XPC',
    },
    'I386' => { 3 => 'ALL', 4 => '486', 4+128 => '486SX',
             0 => 'INTEL_MODEL_ALL', 10 => 'PENTIUM_4',
      5 => 'PENT', 0x16 => 'PENTPRO', 0x36 => 'PENTII_M3', 0x56 => 'PENTII_M5',
    },
    'MIPS' => { 0 => 'ALL', 1 => 'R2300', 2 => 'R2600', 3 => 'R2800', 4 => 'R2000a', },
    'MC680x0' => { 1 => 'ALL', 2 => 'MC68040', 3 => 'MC68030_ONLY', },
    'HPPA' => { 0 => 'ALL', 1 => '7100LC', },
    'ARM' => { 0 => 'ALL', 1 => 'A500_ARCH', 2 => 'A500', 3 => 'A440',
      4 => 'M4', 5 => 'A680', 6 => 'ARMV6', 9 => 'ARMV7',
    },
    'MC88000' => { 0 => 'ALL', 1 => 'MC88100', 2 => 'MC88110', },
    :wtf => { 0 => 'MC98000_ALL', 1 => 'MC98601', },
    'I860' => { 0 => 'ALL', 1 => '860', },
    'RS6000' => { 0 => 'ALL', 1 => 'RS6000', },
    :wtf2 => { 0 => 'SUN4_ALL', 1 => 'SUN4_260', 2 => 'SUN4_110', },
    'SPARC' => { 0 => 'SPARC_ALL', },
    'POWERPC' => { 0 => 'ALL', 1 => '601', 2 => '602', 3 => '603', 4 => '603e',
      5 => '603ev', 6 => '604', 7 => '604e', 8 => '620',
      9 => '750', 10 => '7400', 11 => '7450', 100 => '970',
    },
    'VEO' => { 1 => 'VEO_1', 2 => 'VEO_ALL', },
  }
  SUBCPU['POWERPC64'] = SUBCPU['POWERPC'].dup
  SUBCPU['X86_64'] = SUBCPU['I386'].dup

  SUBCPUFLAG = { 0x80 => 'LIB64' }


  FILETYPE = {
    1 => 'OBJECT', 2 => 'EXECUTE', 3 => 'FVMLIB',
    4 => 'CORE', 5 => 'PRELOAD', 6 => 'DYLIB',
    7 => 'DYLINKER', 8 => 'BUNDLE', 9 => 'DYLIB_STUB',
  }

  FLAGS = {
    0x1 => 'NOUNDEFS', 0x2 => 'INCRLINK', 0x4 => 'DYLDLINK', 0x8 => 'BINDATLOAD',
    0x10 => 'PREBOUND', 0x20 => 'SPLIT_SEGS', 0x40 => 'LAZY_INIT', 0x80 => 'TWOLEVEL',
    0x100 => 'FORCE_FLAT', 0x200 => 'NOMULTIDEFS', 0x400 => 'NOFIXPREBINDING', 0x800 => 'PREBINDABLE',
    0x1000 => 'ALLMODSBOUND', 0x2000 => 'SUBSECTIONS_VIA_SYMBOLS', 0x4000 => 'CANONICAL', 0x8000 => 'WEAK_DEFINES',
    0x10000 => 'BINDS_TO_WEAK', 0x20000 => 'ALLOW_STACK_EXECUTION',
  }

  SEG_PROT = { 1 => 'READ', 2 => 'WRITE', 4 => 'EXECUTE' }

  LOAD_COMMAND = {
    0x1 => 'SEGMENT', 0x2 => 'SYMTAB', 0x3 => 'SYMSEG', 0x4 => 'THREAD',
    0x5 => 'UNIXTHREAD', 0x6 => 'LOADFVMLIB', 0x7 => 'IDFVMLIB', 0x8 => 'IDENT',
    0x9 => 'FVMFILE', 0xa => 'PREPAGE', 0xb => 'DYSYMTAB', 0xc => 'LOAD_DYLIB',
    0xd => 'ID_DYLIB', 0xe => 'LOAD_DYLINKER', 0xf => 'ID_DYLINKER', 0x10 => 'PREBOUND_DYLIB',
    0x11 => 'ROUTINES', 0x12 => 'SUB_FRAMEWORK', 0x13 => 'SUB_UMBRELLA', 0x14 => 'SUB_CLIENT',
    0x15 => 'SUB_LIBRARY', 0x16 => 'TWOLEVEL_HINTS', 0x17 => 'PREBIND_CKSUM',
    0x8000_0018 => 'LOAD_WEAK_DYLIB', 0x19 => 'SEGMENT_64', 0x1a => 'ROUTINES_64',
    0x1b => 'UUID', 0x8000_001c => 'RPATH', 0x1d => 'CODE_SIGNATURE_PTR', 0x1e => 'CODE_SEGMENT_SPLIT_INFO',
    0x8000_001f => 'REEXPORT_DYLIB',
    #0x8000_0000 => 'REQ_DYLD',
  }

  THREAD_FLAVOR = {
    'POWERPC' => { 
      1 => 'THREAD_STATE',
      2 => 'FLOAT_STATE',
      3 => 'EXCEPTION_STATE',
      4 => 'VECTOR_STATE'
    },
    'I386' => {
      1 => 'NEW_THREAD_STATE',
      2 => 'FLOAT_STATE',
      3 => 'ISA_PORT_MAP_STATE',
      4 => 'V86_ASSIST_STATE',
      5 => 'REGS_SEGS_STATE',
      6 => 'THREAD_SYSCALL_STATE',
      7 => 'THREAD_STATE_NONE',
      8 => 'SAVED_STATE',
      -1 & 0xffffffff => 'THREAD_STATE',
      -2 & 0xffffffff => 'THREAD_FPSTATE',
      -3 & 0xffffffff => 'THREAD_EXCEPTSTATE',
      -4 & 0xffffffff => 'THREAD_CTHREADSTATE'
    }
  }

  SYM_SCOPE = { 0 => 'LOCAL', 1 => 'GLOBAL' }
  SYM_TYPE = { 0 => 'UNDF', 2/2 => 'ABS', 0xa/2 => 'INDR', 0xe/2 => 'SECT', 0x1e/2 => 'TYPE' }
  SYM_STAB = { }

  class SerialStruct < Metasm::SerialStruct
    new_int_field :xword
  end

  class Header < SerialStruct
    mem :magic, 4
    decode_hook { |m, h|
      case h.magic
      when MAGIC; m.size = 32 ; m.endianness = :big
      when CIGAM; m.size = 32 ; m.endianness = :little
      when MAGIC64; m.size = 64 ; m.endianness = :big
      when CIGAM64; m.size = 64 ; m.endianness = :little
      else raise InvalidExeFormat, "Invalid Mach-O signature #{h.magic.unpack('H*').first.inspect}"
      end
    }
    word :cputype
    bitfield :word, 0 => :cpusubtype, 24 => :cpusubtypeflag
    words :filetype, :ncmds, :sizeofcmds, :flags
    fld_enum :cputype, CPU
    fld_enum(:cpusubtype) { |m, h| SUBCPU[h.cputype] || {} }
    fld_bits :cpusubtypeflag, SUBCPUFLAG
    fld_enum :filetype, FILETYPE
    fld_bits :flags, FLAGS
    attr_accessor :reserved	# word 64bit only

    def set_default_values(m)
      @magic ||= case [m.size, m.endianness]
           when [32, :big]; MAGIC
           when [32, :little]; CIGAM
           when [64, :big]; MAGIC64
           when [64, :little]; CIGAM64
           end
      @cpusubtype ||= 'ALL'
      @filetype ||= 'EXECUTE'
      @ncmds ||= m.commands.length
      @sizeofcmds ||= m.new_label('sizeofcmds')
      super(m)
    end

    def decode(m)
      super(m)
      @reserved = m.decode_word if m.size == 64
    end
  end

  class LoadCommand < SerialStruct
    words :cmd, :cmdsize
    fld_enum :cmd, LOAD_COMMAND
    attr_accessor :data

    def decode(m)
      super(m)
      ptr = m.encoded.ptr
      if @cmd.kind_of? String and self.class.constants.map { |c| c.to_s }.include? @cmd
        @data = self.class.const_get(@cmd).decode(m)
      end
      m.encoded.ptr = ptr + @cmdsize - 8
    end

    def set_default_values(m)
      @cmd ||= data.class.name.sub(/.*::/, '')
      @cmdsize ||= 'cmdsize'
      super(m)
    end

    def encode(m)
      ed = super(m) 
      ed << @data.encode(m) if @data
      ed.align(m.size >> 3)
      ed.fixup! @cmdsize => ed.length	if @cmdsize.kind_of? String
      ed
    end


    class UUID < SerialStruct
      mem :uuid, 16
    end

    class SEGMENT < SerialStruct
      str :name, 16
      xwords :virtaddr, :virtsize, :fileoff, :filesize
      words :maxprot, :initprot, :nsects, :flags
      fld_bits :maxprot, SEG_PROT
      fld_bits :initprot, SEG_PROT
      attr_accessor :sections, :encoded

      def decode(m)
        super(m)
        @sections = []
        @nsects.times { @sections << SECTION.decode(m, self) }
      end

      def set_default_values(m)
        # TODO (in the caller?) @encoded = @sections.map { |s| s.encoded }.join
        @virtaddr ||= m.new_label('virtaddr')
        @virtsize ||= @encoded.length
        @fileoff  ||= m.new_label('fileoff')
        @filesize ||= @encoded.rawsize
        @sections ||= []
        @nsects   ||= @sections.length
        @maxprot  ||= %w[READ WRITE EXECUTE]
        @initprot ||= %w[READ]
        super(m)
      end

      def encode(m)
        ed = super(m)	# need to call set_default_values before using @sections
        @sections.inject(ed) { |ed_, s| ed_ << s.encode(m) }
      end
    end
    SEGMENT_64 = SEGMENT

    class SECTION < SerialStruct
      str :name, 16
      str :segname, 16
      xwords :addr, :size
      words :offset, :align, :reloff, :nreloc, :flags, :res1, :res2
      attr_accessor :res3	# word 64bit only
      attr_accessor :segment, :encoded

      def decode(m, s)
        super(m)
        @res3 = m.decode_word if m.size == 64
        @segment = s
      end

      def set_default_values(m)
        @segname ||= @segment.name
        # addr, offset, etc = @segment.virtaddr + 42
        super(m)
      end

      def decode_inner(m)
        @encoded = m.encoded[m.addr_to_off(@addr), @size]
      end
    end
    SECTION_64 = SECTION

    class SYMTAB < SerialStruct
      words :symoff, :nsyms, :stroff, :strsize
    end

    class DYSYMTAB < SerialStruct
      words :ilocalsym, :nlocalsym, :iextdefsym, :nextdefsym, :iundefsym, :nundefsym,
        :tocoff, :ntoc, :modtaboff, :nmodtab, :extrefsymoff, :nextrefsyms,
        :indirectsymoff, :nindirectsyms, :extreloff, :nextrel, :locreloff, :nlocrel
    end

    class THREAD < SerialStruct
      words :flavor, :count
      fld_enum(:flavor) { |m, t| THREAD_FLAVOR[m.header.cputype] || {} }
      attr_accessor :ctx
      
      def entrypoint(m)
        @ctx ||= {}
        case m.header.cputype
        when 'I386'; @ctx[:eip]
        when 'X86_64'; @ctx[:rip]
        when 'POWERPC'; @ctx[:srr0]
        when 'ARM'; @ctx[:pc]
        end
      end

      def set_entrypoint(m, ep)
        @ctx ||= {}
        case m.header.cputype
        when 'I386'; @ctx[:eip] = ep
        when 'X86_64'; @ctx[:rip] = ep
        when 'POWERPC'; @ctx[:srr0] = ep
        when 'ARM'; @ctx[:pc] = ep
        end
      end

      def ctx_keys(m)
        case m.header.cputype
        when 'I386'; %w[eax ebx ecx edx edi esi ebp esp ss eflags eip cs ds es fs gs]
        when 'X86_64'; %w[rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15 rip rflags cs fs gs]
        when 'POWERPC'; %w[srr0 srr1 r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23 r24 r25 r26 r27 r28 r29 r30 r31 cr xer lr ctr mq vrsave]
        when 'ARM'; %w[r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 sp lr pc]
        else [*1..@count].map { |i| "r#{i}" }
        end.map { |k| k.to_sym }
      end

      def decode(m)
        super(m)
        @ctx = ctx_keys(m)[0, @count].inject({}) { |ctx, r| ctx.update r => m.decode_xword }
      end

      def set_default_values(m)
        @ctx ||= {}
        ctx_keys(m).each { |k| @ctx[k] ||= 0 }
        @count ||= @ctx.length
        super(m)
      end

      def encode(m)
        ctx_keys(m).inject(super(m)) { |ed, r| ed << m.encode_word(@ctx[r]) }
      end
    end
    UNIXTHREAD = THREAD

    class STRING < SerialStruct
      word :stroff
      attr_accessor :str

      def decode(m)
        ptr = m.encoded.ptr
        super(m)
        ptr = m.encoded.ptr = ptr + @stroff - 8
        @str = m.decode_strz
      end
    end

    class DYLIB < STRING
      word :stroff
      words :timestamp, :cur_version, :compat_version
    end
    LOAD_DYLIB = DYLIB
    ID_DYLIB = DYLIB

    class PREBOUND_DYLIB < STRING
      word :stroff
      word :nmodules
      word :linked_modules
    end

    LOAD_DYLINKER = STRING
    ID_DYLINKER = STRING

    class ROUTINES < SerialStruct
      xwords :init_addr, :init_module, :res1, :res2, :res3, :res4, :res5, :res6
    end
    ROUTINES_64 = ROUTINES

    class TWOLEVEL_HINTS < SerialStruct
      words :offset, :nhints
    end
    class TWOLEVEL_HINT < SerialStruct
      bitfield :word, 0 => :isub_image, 8 => :itoc
    end

    SUB_FRAMEWORK = STRING
    SUB_UMBRELLA = STRING
    SUB_LIBRARY = STRING
    SUB_CLIENT = STRING

    class CODE_SIGNATURE_PTR < SerialStruct
      word :offset
      word :size
      attr_accessor :codesig

      def decode(m)
        ptr = m.encoded.ptr
        super(m)
        m.encoded.ptr = @offset
        @codesig = CODE_SIGNATURE.decode(m)
        m.encoded.ptr = ptr + @size
      end
    end
  end

    class CODE_SIGNATURE < SerialStruct
    word :magic
    word :size
    word :count
    attr_accessor :slots

    def decode(m)
      cs_base = m.encoded.ptr
      e = m.endianness
      m.endianness = :big

      super(m)
      @slots = []
      @count.times { @slots << CS_SLOT_PTR.decode(m, cs_base) }
      m.endianness = e
    end
  end

  class CS_SLOT_PTR < SerialStruct
    word :type
    word :offset
    attr_accessor :body

    def decode(m, cs_base)
      super(m)
      ptr = m.encoded.ptr
      m.encoded.ptr = cs_base + @offset

      if @type == 0
        @body = CS_CODE_DIRECTORY.decode(m)
      else
        @body = CS_SLOT.decode(m)
      end
      m.encoded.ptr = ptr
    end
  end

  class CS_SLOT < SerialStruct
    word :magic
    word :size
    attr_accessor :data

    def decode(m)
      super(m)
      @data = m.encoded.read(@size)
    end
  end

  class CS_CODE_DIRECTORY < SerialStruct
    words :magic, :size, :version
    mem :unk1, 4
    word :hash_offset
    word :name_offset
    word :special_page_count
    word :code_page_count
    mem :unk3, 8
    attr_accessor :name, :cs_slots_hash, :code_hash

    def decode(m)
      super(m)
      ptr = m.encoded.ptr

      m.encoded.ptr += @name_offset - 40
      @name = m.decode_strz
      @cs_slots_hash = m.encoded.read(@special_page_count * 20)

      m.encoded.ptr = ptr + @hash_offset - 40
      @code_hash = m.encoded.read(@size - @hash_offset)

      m.encoded.ptr = ptr
    end
  end

  class Symbol < SerialStruct
    word :nameoff
    bitfield :byte, 0 => :scope, 1 => :type, 5 => :stab
    fld_enum :scope, SYM_SCOPE
    fld_enum :type, SYM_TYPE
    fld_enum :stab, SYM_STAB
    byte :sect
    half :desc
    xword :value
    attr_accessor :name

    def decode(m, buf=nil)
      super(m)
      idx = buf.index(?\0, @nameoff) if buf
      @name = @name = buf[@nameoff..idx-1] if idx
    end
  end

  def encode_byte(val)        Expression[val].encode( :u8, @endianness) end
  def encode_half(val)        Expression[val].encode(:u16, @endianness) end
  def encode_word(val)        Expression[val].encode(:u32, @endianness) end
  def encode_xword(val)       Expression[val].encode((@size == 32 ? :u32 : :u64), @endianness) end
  def decode_byte(edata = @encoded) edata.decode_imm( :u8, @endianness) end
  def decode_half(edata = @encoded) edata.decode_imm(:u16, @endianness) end
  def decode_word(edata = @encoded) edata.decode_imm(:u32, @endianness) end
  def decode_xword(edata= @encoded) edata.decode_imm((@size == 32 ? :u32 : :u64), @endianness) end


  attr_accessor :endianness, :size
  attr_accessor :header, :source
  attr_accessor :segments
  attr_accessor :commands
  attr_accessor :symbols

  def initialize(cpu=nil)
    super(cpu)
    @endianness ||= cpu ? cpu.endianness : :little
    @size ||= cpu ? cpu.size : 32
    @header = Header.new
    @commands = []
    @segments = []
  end

  # decodes the Mach header from the current offset in self.encoded
  def decode_header
    @header.decode self
    @header.ncmds.times { @commands << LoadCommand.decode(self) }
    @commands.each { |cmd|
      e = cmd.data
      case cmd.cmd
      when 'SEGMENT', 'SEGMENT_64'; @segments << e
      end
    }
  end

  def decode
    decode_header
    @segments.each { |s| decode_segment(s) }
    decode_symbols
    decode_relocations
  end

  def decode_symbols
    @symbols = []
    ep_count = 0
    @commands.each { |cmd|
      e = cmd.data
      case cmd.cmd
      when 'SYMTAB'
        @encoded.ptr = e.stroff
        buf = @encoded.read e.strsize
        @encoded.ptr = e.symoff
        e.nsyms.times { @symbols << Symbol.decode(self, buf) }
      when 'THREAD', 'UNIXTHREAD'
        ep_count += 1
        ep = cmd.data.entrypoint(self)
        next if not seg = @segments.find { |seg_| ep >= seg_.virtaddr and ep < seg_.virtaddr + seg_.virtsize }
        seg.encoded.add_export("entrypoint#{"_#{ep_count}" if ep_count >= 2 }", ep - seg.virtaddr)
      end
    }
    @symbols.each { |s|
      next if s.value == 0 or not s.name
      next if not seg = @segments.find { |seg_| s.value >= seg_.virtaddr and s.value < seg_.virtaddr + seg_.virtsize }
      seg.encoded.add_export(s.name, s.value - seg.virtaddr)
    }
  end

  def decode_relocations
  end

  def decode_segment(s)
    s.encoded = @encoded[s.fileoff, s.filesize]
    s.encoded.virtsize = s.virtsize
    s.sections.each { |ss| ss.encoded = @encoded[ss.offset, ss.size] }
  end

  def each_section(&b)
    @segments.each { |s| yield s.encoded, s.virtaddr }
  end

  def get_default_entrypoints
    @commands.find_all { |cmd| cmd.cmd == 'THREAD' or cmd.cmd == 'UNIXTHREAD' }.map { |cmd| cmd.data.entrypoint(self) }
  end

  def cpu_from_headers
    case @header.cputype
    when 'I386'; Ia32.new
    when 'X86_64'; X86_64.new
    when 'POWERPC'; PowerPC.new
    when 'ARM'; ARM.new
    else raise "unsupported cpu #{@header.cputype}"
    end
  end

  def encode(type=nil)
    @encoded = EncodedData.new

    init_header_cpu

    if false and maybeyoureallyneedthis
    segz = LoadCommand::SEGMENT.new
    segz.name = '__PAGEZERO'
    segz.encoded = EncodedData.new
    segz.encoded.virtsize = 0x1000
    segz.initprot = segz.maxprot = 0
    @segments.unshift segz
    end

    # TODO sections -> segments
    @segments.each { |seg|
      cname = (@size == 64 ? 'SEGMENT_64' : 'SEGMENT')
      if not @commands.find { |cmd| cmd.cmd == cname and cmd.data == seg }
        cmd = LoadCommand.new
        cmd.cmd = cname
        cmd.data = seg
        @commands << cmd
      end
    }

    binding = {}
    @encoded << @header.encode(self)

    first = @segments.find { |seg| seg.encoded.rawsize > 0 }

    first.virtsize = new_label('virtsize')
    first.filesize = new_label('filesize')

    hlen = @encoded.length
    @commands.each { |cmd| @encoded << cmd.encode(self) }
    binding[@header.sizeofcmds] = @encoded.length - hlen if @header.sizeofcmds.kind_of? String

    # put header in first segment
    first.encoded = @encoded << first.encoded

    @encoded = EncodedData.new

    addr = @encoded.length
    @segments.each { |seg|
      seg.encoded.align 0x1000
      binding[seg.virtaddr] = addr
      binding[seg.virtsize] = seg.encoded.length if seg.filesize.kind_of? String
      binding[seg.fileoff] = @encoded.length
      binding[seg.filesize] = seg.encoded.rawsize if seg.filesize.kind_of? String
      binding.update seg.encoded.binding(addr)
      @encoded << seg.encoded[0, seg.encoded.rawsize]
      @encoded.align 0x1000
      addr += seg.encoded.length
    }

    @encoded.fixup! binding
    @encoded.data
  end

  def parse_init
    # allow the user to specify a section, falls back to .text if none specified
    if not defined? @cursource or not @cursource
      @cursource = Object.new
      class << @cursource
        attr_accessor :exe
        def <<(*a)
          t = Preprocessor::Token.new(nil)
          t.raw = '.text'
          exe.parse_parser_instruction t
          exe.cursource.send(:<<, *a)
        end
      end
      @cursource.exe = self
    end

    @source ||= {}

    init_header_cpu		# for '.entrypoint'

    super()
  end

  def init_header_cpu
    @header.cputype ||= case @cpu.shortname
            when 'ia32'; 'I386'
            when 'x64'; 'X86_64'
            when 'powerpc'; 'POWERPC'
            when 'arm'; 'ARM'
            end
  end

  # handles macho meta-instructions
  #
  # syntax:
  #   .section "<name>" [<perms>]
  #     change current section (where normal instruction/data are put)
  #     perms = list of 'r' 'w' 'x', may be prefixed by 'no'
  #     shortcuts: .text .data .rodata .bss
  #   .entrypoint [<label>]
  #     defines the program entrypoint to the specified label / current location
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
      sname = instr.raw.upcase.sub('.', '__')
      if not @segments.find { |s| s.kind_of? LoadCommand::SEGMENT and s.name == sname }
        s = LoadCommand::SEGMENT.new
        s.name = sname
        s.encoded = EncodedData.new
        s.initprot = case sname
          when '__TEXT'; %w[READ EXECUTE]
          when '__DATA', '__BSS'; %w[READ WRITE]
          when '__RODATA'; %w[READ]
          end
        s.maxprot = %w[READ WRITE EXECUTE]
        @segments << s
      end
      @cursource = @source[sname] ||= []
      check_eol[] if instr.backtrace  # special case for magic @cursource

    when '.section'
      # .section <section name|"section name"> [(no)wxalloc] [base=<expr>]
      sname = readstr[]
      if not s = @segments.find { |s_| s_.name == sname }
        s = LoadCommand::SEGMENT.new
        s.name = sname
        s.encoded = EncodedData.new
        s.initprot = %w[READ]
        s.maxprot = %w[READ WRITE EXECUTE]
        @segments << s
      end
      loop do
        @lexer.skip_space
        break if not tok = @lexer.nexttok or tok.type != :string
        case @lexer.readtok.raw.downcase
        when /^(no)?(r)?(w)?(x)?$/
          ar = []
          ar << 'READ' if $2
          ar << 'WRITE' if $3
          ar << 'EXECINSTR' if $4
          if $1; s.initprot -= ar
          else   s.initprot |= ar
          end
        else raise instr, 'unknown specifier'
        end
      end
      @cursource = @source[sname] ||= []
      check_eol[]

    when '.entrypoint'	# XXX thread-specific
      # ".entrypoint <somelabel/expression>" or ".entrypoint" (here)
      @lexer.skip_space
      if tok = @lexer.nexttok and tok.type == :string
        raise instr if not entrypoint = Expression.parse(@lexer)
      else
        entrypoint = new_label('entrypoint')
        @cursource << Label.new(entrypoint, instr.backtrace.dup)
      end
      if not cmd = @commands.find { |cmd_| cmd_.cmd == 'THREAD' or cmd_.cmd == 'UNIXTHREAD' }
        cmd = LoadCommand.new
        cmd.cmd = 'UNIXTHREAD'	# UNIXTHREAD creates a stack
        cmd.data = LoadCommand::THREAD.new
        cmd.data.ctx = {}
        cmd.data.flavor = 'NEW_THREAD_STATE'	# XXX i386 specific
        @commands << cmd
      end
      cmd.data.set_entrypoint(self, entrypoint)
      check_eol[]

    else super(instr)
    end
  end

  # assembles the hash self.source to a section array
  def assemble(*a)
    parse(*a) if not a.empty?
    @source.each { |k, v|
      raise "no segment named #{k} ?" if not s = @segments.find { |s_| s_.name == k }
      s.encoded << assemble_sequence(v, @cpu)
      v.clear
    }
  end
end
MACHO = MachO



class UniversalBinary < ExeFormat
  MAGIC = "\xca\xfe\xba\xbe"	# 0xcafebabe

  class Header < SerialStruct
    mem :magic, 4
    word :nfat_arch

    def decode(u)
      super(u)
      raise InvalidExeFormat, "Invalid UniversalBinary signature #{@magic.unpack('H*').first.inspect}" if @magic != MAGIC
    end
  end
  class FatArch < SerialStruct
    words :cputype, :subcpu, :offset, :size, :align
    fld_enum :cputype, MachO::CPU
    fld_enum(:subcpu) { |x, a| MachO::SUBCPU[a.cputype] || {} }
    attr_accessor :encoded
  end

  def encode_word(val)        Expression[val].encode(:u32, @endianness) end
  def decode_word(edata = @encoded) edata.decode_imm(:u32, @endianness) end

  attr_accessor :endianness, :encoded, :header, :archive
  def initialize
    @endianness = :big
    super()
  end

  def decode
    @header = Header.decode(self)
    @archive = []
    @header.nfat_arch.times { @archive << FatArch.decode(self) }
    @archive.each { |a|
      a.encoded = @encoded[a.offset, a.size] || EncodedData.new
    }
  end

  def [](i) AutoExe.decode(@archive[i].encoded) if @archive[i] end
  def <<(exe) @archive << exe end

  def self.autoexe_load(*a)
    ub = super(*a)
    ub.decode
    # TODO have a global callback or whatever to prompt the user
    # which file he wants to load in the dasm
    puts "UniversalBinary: using 1st archive member" if $VERBOSE
    AutoExe.load(ub.archive[0].encoded)
  end

end
end
