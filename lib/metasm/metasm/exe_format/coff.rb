#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/exe_format/main'

module Metasm
# the COFF object file format
# mostly used on windows (PE/COFF)
class COFF < ExeFormat
  CHARACTERISTIC_BITS = {
    0x0001 => 'RELOCS_STRIPPED',    0x0002 => 'EXECUTABLE_IMAGE',
    0x0004 => 'LINE_NUMS_STRIPPED', 0x0008 => 'LOCAL_SYMS_STRIPPED',
    0x0010 => 'AGGRESSIVE_WS_TRIM', 0x0020 => 'LARGE_ADDRESS_AWARE',
    0x0040 => 'x16BIT_MACHINE',     0x0080 => 'BYTES_REVERSED_LO',
    0x0100 => 'x32BIT_MACHINE',     0x0200 => 'DEBUG_STRIPPED',
    0x0400 => 'REMOVABLE_RUN_FROM_SWAP', 0x0800 => 'NET_RUN_FROM_SWAP',
    0x1000 => 'SYSTEM',             0x2000 => 'DLL',
    0x4000 => 'UP_SYSTEM_ONLY',     0x8000 => 'BYTES_REVERSED_HI'
  }

  MACHINE = {
    0x0   => 'UNKNOWN',   0x184 => 'ALPHA',   0x1c0 => 'ARM',
    0x1d3 => 'AM33',      0x8664=> 'AMD64',   0xebc => 'EBC',
    0x9041=> 'M32R',      0x1f1 => 'POWERPCFP',
    0x284 => 'ALPHA64',   0x14c => 'I386',    0x200 => 'IA64',
    0x268 => 'M68K',      0x266 => 'MIPS16',  0x366 => 'MIPSFPU',
    0x466 => 'MIPSFPU16', 0x1f0 => 'POWERPC', 0x162 => 'R3000',
    0x166 => 'R4000',     0x168 => 'R10000',  0x1a2 => 'SH3',
    0x1a3 => 'SH3DSP',    0x1a6 => 'SH4',     0x1a8 => 'SH5',
    0x1c2 => 'THUMB',     0x169 => 'WCEMIPSV2'
  }

  # PE+ is for 64bits address spaces
  SIGNATURE = { 0x10b => 'PE', 0x20b => 'PE+', 0x107 => 'ROM' }

  SUBSYSTEM = {
    0 => 'UNKNOWN',     1 => 'NATIVE',    2 => 'WINDOWS_GUI',
    3 => 'WINDOWS_CUI', 5 => 'OS/2_CUI',  7 => 'POSIX_CUI',
    8 => 'WIN9X_DRIVER', 9 => 'WINDOWS_CE_GUI',
    10 => 'EFI_APPLICATION',
    11 => 'EFI_BOOT_SERVICE_DRIVER',  12 => 'EFI_RUNTIME_DRIVER',
    13 => 'EFI_ROM', 14 => 'XBOX'
  }

  DLL_CHARACTERISTIC_BITS = {
    0x40 => 'DYNAMIC_BASE', 0x80 => 'FORCE_INTEGRITY', 0x100 => 'NX_COMPAT',
    0x200 => 'NO_ISOLATION', 0x400 => 'NO_SEH', 0x800 => 'NO_BIND',
    0x2000 => 'WDM_DRIVER', 0x8000 => 'TERMINAL_SERVER_AWARE'
  }

  BASE_RELOCATION_TYPE = { 0 => 'ABSOLUTE', 1 => 'HIGH', 2 => 'LOW', 3 => 'HIGHLOW',
    4 => 'HIGHADJ', 5 => 'MIPS_JMPADDR', 9 => 'MIPS_JMPADDR16', 10 => 'DIR64'
  }

  RELOCATION_TYPE = Hash.new({}).merge(
    'AMD64' => { 0 => 'ABSOLUTE', 1 => 'ADDR64', 2 => 'ADDR32', 3 => 'ADDR32NB',
      4 => 'REL32', 5 => 'REL32_1', 6 => 'REL32_2', 7 => 'REL32_3',
      8 => 'REL32_4', 9 => 'REL32_5', 10 => 'SECTION', 11 => 'SECREL',
      12 => 'SECREL7', 13 => 'TOKEN', 14 => 'SREL32', 15 => 'PAIR',
      16 => 'SSPAN32' },
    'ARM' => { 0 => 'ABSOLUTE', 1 => 'ADDR32', 2 => 'ADDR32NB', 3 => 'BRANCH24',
      4 => 'BRANCH11', 14 => 'SECTION', 15 => 'SECREL' },
    'I386' => { 0 => 'ABSOLUTE', 1 => 'DIR16', 2 => 'REL16', 6 => 'DIR32',
      7 => 'DIR32NB', 9 => 'SEG12', 10 => 'SECTION', 11 => 'SECREL',
      12 => 'TOKEN', 13 => 'SECREL7', 20 => 'REL32' }
  )

  # lsb of symbol type, unused
  SYMBOL_BTYPE = { 0 => 'NULL', 1 => 'VOID', 2 => 'CHAR', 3 => 'SHORT',
    4 => 'INT', 5 => 'LONG', 6 => 'FLOAT', 7 => 'DOUBLE', 8 => 'STRUCT',
    9 => 'UNION', 10 => 'ENUM', 11 => 'MOE', 12 => 'BYTE', 13 => 'WORD',
    14 => 'UINT', 15 => 'DWORD'}
  SYMBOL_TYPE = { 0 => 'NULL', 1 => 'POINTER', 2 => 'FUNCTION', 3 => 'ARRAY' }
  SYMBOL_SECTION = { 0 => 'UNDEF', 0xffff => 'ABS', 0xfffe => 'DEBUG' }
  SYMBOL_STORAGE = { 0xff => 'EOF', 0 => 'NULL', 1 => 'AUTO', 2 => 'EXTERNAL',
    3 => 'STATIC', 4 => 'REGISTER', 5 => 'EXT_DEF', 6 => 'LABEL',
    7 => 'UNDEF_LABEL', 8 => 'STRUCT_MEMBER', 9 => 'ARGUMENT', 10 => 'STRUCT_TAG',
    11 => 'UNION_MEMBER', 12 => 'UNION_TAG', 13 => 'TYPEDEF', 14 => 'UNDEF_STATIC',
    15 => 'ENUM_TAG', 16 => 'ENUM_MEMBER', 17 => 'REG_PARAM', 18 => 'BIT_FIELD',
    100 => 'BLOCK', 101 => 'FUNCTION', 102 => 'END_STRUCT',
    103 => 'FILE', 104 => 'SECTION', 105 => 'WEAK_EXT',
  }

  DEBUG_TYPE = { 0 => 'UNKNOWN', 1 => 'COFF', 2 => 'CODEVIEW', 3 => 'FPO', 4 => 'MISC',
    5 => 'EXCEPTION', 6 => 'FIXUP', 7 => 'OMAP_TO_SRC', 8 => 'OMAP_FROM_SRC',
    9 => 'BORLAND', 10 => 'RESERVED10', 11 => 'CLSID' }

  DIRECTORIES = %w[export_table import_table resource_table exception_table certificate_table
        base_relocation_table debug architecture global_ptr tls_table load_config
        bound_import iat delay_import com_runtime reserved]

  SECTION_CHARACTERISTIC_BITS = {
    0x20 => 'CONTAINS_CODE', 0x40 => 'CONTAINS_DATA', 0x80 => 'CONTAINS_UDATA',
    0x100 => 'LNK_OTHER', 0x200 => 'LNK_INFO', 0x800 => 'LNK_REMOVE',
    0x1000 => 'LNK_COMDAT', 0x8000 => 'GPREL',
    0x20000 => 'MEM_PURGEABLE|16BIT', 0x40000 => 'MEM_LOCKED', 0x80000 => 'MEM_PRELOAD',
    0x100000 => 'ALIGN_1BYTES',    0x200000 => 'ALIGN_2BYTES',
    0x300000 => 'ALIGN_4BYTES',    0x400000 => 'ALIGN_8BYTES',
    0x500000 => 'ALIGN_16BYTES',   0x600000 => 'ALIGN_32BYTES',
    0x700000 => 'ALIGN_64BYTES',   0x800000 => 'ALIGN_128BYTES',
    0x900000 => 'ALIGN_256BYTES',  0xA00000 => 'ALIGN_512BYTES',
    0xB00000 => 'ALIGN_1024BYTES', 0xC00000 => 'ALIGN_2048BYTES',
    0xD00000 => 'ALIGN_4096BYTES', 0xE00000 => 'ALIGN_8192BYTES',
    0x01000000 => 'LNK_NRELOC_OVFL', 0x02000000 => 'MEM_DISCARDABLE',
    0x04000000 => 'MEM_NOT_CACHED',  0x08000000 => 'MEM_NOT_PAGED',
    0x10000000 => 'MEM_SHARED',      0x20000000 => 'MEM_EXECUTE',
    0x40000000 => 'MEM_READ',        0x80000000 => 'MEM_WRITE'
  }
  # NRELOC_OVFL means there are more than 0xffff reloc
  # the reloc count must be set to 0xffff, and the real reloc count
  # is the VA of the first relocation

  ORDINAL_REGEX = /^Ordinal_(\d+)$/

  COMIMAGE_FLAGS = {
    1 => 'ILONLY', 2 => '32BITREQUIRED', 4 => 'IL_LIBRARY',
    8 => 'STRONGNAMESIGNED', 16 => 'NATIVE_ENTRYPOINT',
    0x10000 => 'TRACKDEBUGDATA'
  }

  class SerialStruct < Metasm::SerialStruct
    new_int_field :xword
  end

  class Header < SerialStruct
    half :machine, 'I386', MACHINE
    half :num_sect
    words :time, :ptr_sym, :num_sym
    half :size_opthdr
    half :characteristics
    fld_bits :characteristics, CHARACTERISTIC_BITS
  end

  # present in linked files (exe/dll/kmod)
  class OptionalHeader < SerialStruct
    half :signature, 'PE', SIGNATURE
    bytes :link_ver_maj, :link_ver_min
    words :code_size, :data_size, :udata_size, :entrypoint, :base_of_code
    # base_of_data does not exist in 64-bit
    new_field(:base_of_data, lambda { |exe, hdr| exe.decode_word if exe.bitsize != 64 }, lambda { |exe, hdr, val| exe.encode_word(val) if exe.bitsize != 64 }, 0)
    # NT-specific fields
    xword :image_base
    words :sect_align, :file_align
    halfs :os_ver_maj, :os_ver_min, :img_ver_maj, :img_ver_min, :subsys_maj, :subsys_min
    words :reserved, :image_size, :headers_size, :checksum
    half :subsystem, 0, SUBSYSTEM
    half :dll_characts
    fld_bits :dll_characts, DLL_CHARACTERISTIC_BITS
    xwords :stack_reserve, :stack_commit, :heap_reserve, :heap_commit
    words :ldrflags, :numrva
  end

  # COFF relocatable object symbol (table offset found in the Header.ptr_sym)
  class Symbol < SerialStruct
    str :name, 8	# if the 1st 4 bytes are 0, the word at 4...8 is the name index in the string table
    word :value
    half :sec_nr
    fld_enum :sec_nr, SYMBOL_SECTION
    bitfield :half, 0 => :type_base, 4 => :type
    fld_enum :type_base, SYMBOL_BTYPE
    fld_enum :type, SYMBOL_TYPE
    bytes :storage, :nr_aux
    fld_enum :storage, SYMBOL_STORAGE

    attr_accessor :aux
  end

  class Section < SerialStruct
    str :name, 8
    words :virtsize, :virtaddr, :rawsize, :rawaddr, :relocaddr, :linenoaddr
    halfs :relocnr, :linenonr
    word :characteristics
    fld_bits :characteristics, SECTION_CHARACTERISTIC_BITS

    attr_accessor :encoded, :relocs
  end

  # COFF relocatable object relocation (per section, see relocaddr/relocnr)
  class RelocObj < SerialStruct
    word :va
    word :symidx
    half :type
    fld_enum(:type) { |coff, rel| RELOCATION_TYPE[coff.header.machine] || {} }
    attr_accessor :sym
  end

  # lists the functions/addresses exported to the OS (pendant of ImportDirectory)
  class ExportDirectory < SerialStruct
    words :reserved, :timestamp
    halfs :version_major, :version_minor
    words :libname_p, :ordinal_base, :num_exports, :num_names, :func_p, :names_p, :ord_p
    attr_accessor :libname, :exports

    class Export
      attr_accessor :forwarder_lib, :forwarder_ordinal, :forwarder_name, :target, :target_rva, :name_p, :name, :ordinal
    end
  end

  # contains the name of dynamic libraries required by the program, and the function to import from them
  class ImportDirectory < SerialStruct
    words :ilt_p, :timestamp, :firstforwarder, :libname_p, :iat_p
    fld_default :firstforwarder, 0xffff_ffff
    attr_accessor :libname, :imports, :iat

    class Import
      attr_accessor :ordinal, :hint, :hintname_p, :name, :target, :thunk
    end
  end

  # tree-like structure, holds all misc data the program might need (icons, cursors, version information)
  # conventionnally structured in a 3-level depth structure:
  #  I resource type (icon/cursor/etc, see +TYPES+)
  #  II resource id (icon n1, icon 'toto', ...)
  #  III language-specific version (icon n1 en, icon n1 en-dvorak...)
  class ResourceDirectory < SerialStruct
    words :characteristics, :timestamp
    halfs :major_version, :minor_version, :nr_names, :nr_id
    attr_accessor :entries
    attr_accessor :curoff_label	# internal use, in encoder

    class Entry
      attr_accessor :name_p, :name, :name_w,
        :id, :subdir_p, :subdir, :dataentry_p,
        :data_p, :data, :codepage, :reserved
    end
  end

  # array of relocations to apply to an executable file
  # when it is loaded at an address that is not its preferred_base_address
  class RelocationTable < SerialStruct
    word :base_addr
    attr_accessor :relocs

    class Relocation < SerialStruct
      bitfield :half, 0 => :offset, 12 => :type
      fld_enum :type, BASE_RELOCATION_TYPE
    end
  end

  class DebugDirectory < SerialStruct
    words :characteristics, :timestamp
    halfs :major_version, :minor_version
    words :type, :size_of_data, :addr, :pointer
    fld_enum :type, DEBUG_TYPE

    attr_accessor :data

    class NB10 < SerialStruct
      word :offset
      word :signature
      word :age
      strz :pdbfilename
    end

    class RSDS < SerialStruct
      mem :guid, 16
      word :age
      strz :pdbfilename
    end
  end

  class TLSDirectory < SerialStruct
    xwords :start_va, :end_va, :index_addr, :callback_p
    words :zerofill_sz, :characteristics

    attr_accessor :callbacks
  end

  # the 'load configuration' directory (used for SafeSEH)
  class LoadConfig < SerialStruct
    words :signature, :timestamp
    halfs :major_version, :minor_version
    words :globalflags_clear, :globalflags_set, :critsec_timeout
    # lockpfxtable is an array of VA of LOCK prefixes, to be nopped on singleproc machines (!)
    xwords :decommitblock, :decommittotal, :lockpfxtable, :maxalloc, :maxvirtmem, :process_affinity_mask
    word :process_heap_flags
    halfs :service_pack_id, :reserved
    xwords :editlist, :security_cookie, :sehtable_p, :sehcount

    attr_accessor :safeseh
  end

  class DelayImportDirectory < SerialStruct
    words :attributes, :libname_p, :handle_p, :iat_p, :int_p, :biat_p, :uiat_p, :timestamp

    attr_accessor :libname
  end

  # structure defining entrypoints and stuff for .net binaries
  class Cor20Header < SerialStruct
    word :size
    halfs :major_version, :minor_version	# runtime version
    words :metadata_rva, :metadata_sz
    word :flags
    fld_bits :flags, COMIMAGE_FLAGS
    word :entrypoint	# RVA to native or managed ep, depending on flags
    words :resources_rva, :resources_sz
    words :strongnamesig_rva, :strongnamesig_sz
    words :codemgr_rva, :codemgr_sz
    words :vtfixup_rva, :vtfixup_sz
    words :eatjumps_rva, :eatjumps_sz
    words :managednativehdr_rva, :managednativehdr_sz

    attr_accessor :metadata, :resources, :strongnamesig, :codemgr, :vtfixup, :eatjumps, :managednativehdr
  end

  # for the icon, the one that appears in the explorer is
  #  (NT) the one with the lowest ID
  #  (98) the first to appear in the table
  class ResourceDirectory
    def to_hash(depth=0)
      map =	case depth
        when 0; TYPE
        when 1; {}	# resource-id
        when 2; {}	# lang
        else {}
        end
      @entries.inject({}) { |h, e|
        k = e.id ? map.fetch(e.id, e.id) : e.name ? e.name : e.name_w
        v = e.subdir ? e.subdir.to_hash(depth+1) : e.data
        h.update k => v
      }
    end

    def self.from_hash(h, depth=0)
      map =	case depth
        when 0; TYPE
        when 1; {}	# resource-id
        when 2; {}	# lang
        else {}
        end
      ret = new
      ret.entries = h.map { |k, v|
        e = Entry.new
        k.kind_of?(Integer) ? (e.id = k) : map.index(k) ? (e.id = map.index(k)) : (e.name = k)	# name_w ?
        v.kind_of?(Hash) ? (e.subdir = from_hash(v, depth+1)) : (e.data = v)
        e
      }
      ret
    end

    # returns a string with the to_hash key tree
    def to_s
      to_s_a(0).join("\n")
    end

    def to_s_a(depth)
      @entries.map { |e|
        ar = []
        ar << if e.id
          if depth == 0 and TYPE.has_key?(e.id); "#{e.id.to_s} (#{TYPE[e.id]})".ljust(18)
          else e.id.to_s.ljust(5)
          end
        else (e.name || e.name_w).inspect
        end
        if e.subdir
          sa = e.subdir.to_s_a(depth+1)
          if sa.length == 1
            ar.last << " | #{sa.first}"
          else
            ar << sa.map { |s| '    ' + s }
          end
        elsif e.data.length > 16
          ar.last << " #{e.data[0, 8].inspect}... <#{e.data.length} bytes>"
        else
          ar.last << ' ' << e.data.inspect
        end
        ar
      }.flatten
    end

    TYPE = {
      1 => 'CURSOR', 2 => 'BITMAP', 3 => 'ICON', 4 => 'MENU',
      5 => 'DIALOG', 6 => 'STRING', 7 => 'FONTDIR', 8 => 'FONT',
      9 => 'ACCELERATOR', 10 => 'RCADATA', 11 => 'MESSAGETABLE',
      12 => 'GROUP_CURSOR', 14 => 'GROUP_ICON', 16 => 'VERSION',
      17 => 'DLGINCLUDE', 19 => 'PLUGPLAY', 20 => 'VXD',
      21 => 'ANICURSOR', 22 => 'ANIICON', 23 => 'HTML',
      24 => 'MANIFEST'
    }

    ACCELERATOR_BITS = {
      1 => 'VIRTKEY', 2 => 'NOINVERT', 4 => 'SHIFT', 8 => 'CTRL',
      16 => 'ALT', 128 => 'LAST'
    }

    # cursor = raw data, cursor_group = header , pareil pour les icons
    class Cursor
      attr_accessor :xhotspot, :yhotspot, :data
    end
  end

  attr_accessor :header, :optheader, :directory, :sections, :endianness, :symbols, :bitsize,
    :export, :imports, :resource, :certificates, :relocations, :debug, :tls, :loadconfig, :delayimports, :com_header

  # boolean, set to true to have #decode() ignore the base_relocs directory
  attr_accessor :nodecode_relocs

  def initialize(*a)
    cpu = a.grep(CPU).first
    @nodecode_relocs = true if a.include? :nodecode_relocs

    @directory = {}	# DIRECTORIES.key => [rva, size]
    @sections = []
    @endianness = cpu ? cpu.endianness : :little
    @bitsize = cpu ? cpu.size : 32
    @header = Header.new
    @optheader = OptionalHeader.new
    super(cpu)
  end

  def shortname; 'coff'; end
end

# the COFF archive file format
# maybe used in .lib files (they hold binary import information for libraries)
# used for unix .a static library files (with no 2nd linker and newline-separated longnames)
class COFFArchive < ExeFormat
  class Member < SerialStruct
    mem :name, 16
    mem :date, 12
    mem :uid, 6
    mem :gid, 6
    mem :mode, 8
    mem :size, 10
    mem :eoh, 2

    attr_accessor :offset, :encoded
  end

  class ImportHeader < SerialStruct
    halfs :sig1, :sig2, :version, :machine
    words :timestamp, :size_of_data
    half :hint
    bitfield :half, 0 => :reserved, 11 => :name_type, 14 => :type
    #fld_enum :type, IMPORT_TYPE
    #fld_enum :name_type, NAME_TYPE
    strz :symname
    strz :libname
  end

  attr_accessor :members, :signature, :first_linker, :second_linker, :longnames

  # return the 1st member whose name is name
  def member(name)
    @members.find { |m| m.name == name }
  end
end
end

require 'metasm/exe_format/coff_encode'
require 'metasm/exe_format/coff_decode'
