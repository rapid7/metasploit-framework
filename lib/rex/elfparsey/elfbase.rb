# -*- coding: binary -*-

require 'rex/struct2'

module Rex
module ElfParsey
class ElfBase

  # ELF Header

  ELF_HEADER_SIZE = 52

  EI_NIDENT = 16

  ELF32_EHDR_LSB = Rex::Struct2::CStructTemplate.new(
    [ 'string',  'e_ident',     EI_NIDENT, '' ],
    [ 'uint16v', 'e_type',      0 ],
    [ 'uint16v', 'e_machine',   0 ],
    [ 'uint32v', 'e_version',   0 ],
    [ 'uint32v', 'e_entry',     0 ],
    [ 'uint32v', 'e_phoff',     0 ],
    [ 'uint32v', 'e_shoff',     0 ],
    [ 'uint32v', 'e_flags',     0 ],
    [ 'uint16v', 'e_ehsize',    0 ],
    [ 'uint16v', 'e_phentsize', 0 ],
    [ 'uint16v', 'e_phnum',     0 ],
    [ 'uint16v', 'e_shentsize', 0 ],
    [ 'uint16v', 'e_shnum',     0 ],
    [ 'uint16v', 'e_shstrndx',  0 ]
  )

  ELF32_EHDR_MSB = Rex::Struct2::CStructTemplate.new(
    [ 'string',  'e_ident',     EI_NIDENT, '' ],
    [ 'uint16n', 'e_type',      0 ],
    [ 'uint16n', 'e_machine',   0 ],
    [ 'uint32n', 'e_version',   0 ],
    [ 'uint32n', 'e_entry',     0 ],
    [ 'uint32n', 'e_phoff',     0 ],
    [ 'uint32n', 'e_shoff',     0 ],
    [ 'uint32n', 'e_flags',     0 ],
    [ 'uint16n', 'e_ehsize',    0 ],
    [ 'uint16n', 'e_phentsize', 0 ],
    [ 'uint16n', 'e_phnum',     0 ],
    [ 'uint16n', 'e_shentsize', 0 ],
    [ 'uint16n', 'e_shnum',     0 ],
    [ 'uint16n', 'e_shstrndx',  0 ]
  )

  # e_type  This member identifies the object file type

  ET_NONE   = 0       # No file type
  ET_REL    = 1       # Relocatable file
  ET_EXEC   = 2       # Executable file
  ET_DYN    = 3       # Shared object file
  ET_CORE   = 4       # Core file
  ET_LOPROC = 0xff00  # Processor-specific
  ET_HIPROC = 0xffff  # Processor-specific

  #
  # e_machine  This member's value specifies the required architecture for an
  # individual file.
  #

  # ET_NONE        = 0   # No machine
  EM_M32         = 1   # AT&T WE 32100
  EM_SPARC       = 2   # SPARC
  EM_386         = 3   # Intel Architecture
  EM_68K         = 4   # Motorola 68000
  EM_88K         = 5   # Motorola 88000
  EM_860         = 7   # Intel 80860
  EM_MIPS        = 8   # MIPS RS3000 Big-Endian
  EM_MIPS_RS4_BE = 10  # MIPS RS4000 Big-Endian

  # e_version  This member identifies the object file version

  EV_NONE    = 0  # Invalid version
  EV_CURRENT = 1  # Current version


  # ELF Identification

  # e_ident[]  Identification indexes

  EI_MAG0    = 0   # File identification
  EI_MAG1    = 1   # File identification
  EI_MAG2    = 2   # File identification
  EI_MAG3    = 3   # File identification
  EI_CLASS   = 4   # File class
  EI_DATA    = 5   # Data encoding
  EI_VERSION = 6   # File version
  EI_PAD     = 7   # Start of padding bytes
  # EI_NIDENT  = 16  # Size of e_ident[]

  #
  # EI_MAG0 to EI_MAG3  A file's first 4 bytes hold a "magic number",
  # identifying the file as an ELF object file.
  #

  ELFMAG0 = 0x7f  # e_ident[EI_MAG0]
  ELFMAG1 = ?E   # e_ident[EI_MAG1]
  ELFMAG2 = ?L   # e_ident[EI_MAG2]
  ELFMAG3 = ?F   # e_ident[EI_MAG3]

  ELFMAG = ELFMAG0.chr + ELFMAG1.chr + ELFMAG2.chr + ELFMAG3.chr

  # EI_CLASS  Identifies the file's class, or capacity

  ELFCLASSNONE = 0  # Invalid class
  ELFCLASS32   = 1  # 32-bit objects
  ELFCLASS64   = 2  # 64-bit objects

  #
  # EI_DATA  Specifies the data encoding of the processor-specific data in
  # the object file. The following encodings are currently defined.
  #

  ELFDATANONE = 0  # Invalid data encoding
  ELFDATA2LSB = 1  # Least significant byte first
  ELFDATA2MSB = 2  # Most significant byte first

  class GenericStruct
    attr_accessor :struct
    def initialize(_struct)
      self.struct = _struct
    end

    # The following methods are just pass-throughs for struct

    # Access a value
    def v
      struct.v

    end

    # Access a value by array
    def [](*args)
      struct[*args]
    end

    # Obtain an array of all fields
    def keys
      struct.keys
    end

    def method_missing(meth, *args)
      v[meth.to_s] || (raise NoMethodError.new, meth)
    end
  end

  class GenericHeader < GenericStruct
  end

  class ElfHeader < GenericHeader
    def initialize(rawdata)

      # Identify the data encoding and parse ELF Header
      elf_header = ELF32_EHDR_LSB.make_struct

      if !elf_header.from_s(rawdata)
        raise ElfHeaderError, "Couldn't parse ELF Header", caller
      end

      if elf_header.v['e_ident'][EI_DATA,1].unpack('C')[0] == ELFDATA2MSB
        elf_header = ELF32_EHDR_MSB.make_struct

        if !elf_header.from_s(rawdata)
          raise ElfHeaderError, "Couldn't parse ELF Header", caller
        end
      end

      unless [ ELFDATA2LSB, ELFDATA2MSB ].include?(
      elf_header.v['e_ident'][EI_DATA,1].unpack('C')[0])
        raise ElfHeaderError, "Invalid data encoding", caller
      end

      # Identify the file as an ELF object file
      unless elf_header.v['e_ident'][EI_MAG0, 4] == ELFMAG
        raise ElfHeaderError, 'Invalid magic number', caller
      end

      self.struct = elf_header
    end

    def e_ident
      struct.v['e_ident']
    end

  end


  # Program Header

  PROGRAM_HEADER_SIZE = 32

  ELF32_PHDR_LSB = Rex::Struct2::CStructTemplate.new(
    [ 'uint32v', 'p_type',   0 ],
    [ 'uint32v', 'p_offset', 0 ],
    [ 'uint32v', 'p_vaddr',  0 ],
    [ 'uint32v', 'p_paddr',  0 ],
    [ 'uint32v', 'p_filesz', 0 ],
    [ 'uint32v', 'p_memsz',  0 ],
    [ 'uint32v', 'p_flags',  0 ],
    [ 'uint32v', 'p_align',  0 ]
  )

  ELF32_PHDR_MSB = Rex::Struct2::CStructTemplate.new(
    [ 'uint32n', 'p_type',   0 ],
    [ 'uint32n', 'p_offset', 0 ],
    [ 'uint32n', 'p_vaddr',  0 ],
    [ 'uint32n', 'p_paddr',  0 ],
    [ 'uint32n', 'p_filesz', 0 ],
    [ 'uint32n', 'p_memsz',  0 ],
    [ 'uint32n', 'p_flags',  0 ],
    [ 'uint32n', 'p_align',  0 ]
  )

  #
  # p_type  This member tells what kind of segment this array element
  # describes or how to interpret the array element's information.
  #

  # Segment Types

  PT_NULL    = 0
  PT_LOAD    = 1
  PT_DYNAMIC = 2
  PT_INTERP  = 3
  PT_NOTE    = 4
  PT_SHLIB   = 5
  PT_PHDR    = 6
  PT_LOPROC  = 0x70000000
  PT_HIPROC  = 0x7fffffff

  class ProgramHeader < GenericHeader
    def initialize(rawdata, ei_data)
      # Identify the data encoding and parse Program Header
      if ei_data == ELFDATA2LSB
        program_header = ELF32_PHDR_LSB.make_struct
      elsif ei_data == ELFDATA2MSB
        program_header = ELF32_PHDR_MSB.make_struct
      else
        raise ElfHeaderError, "Invalid data encoding", caller
      end

      if !program_header.from_s(rawdata)
        raise ProgramHeaderError, "Couldn't parse Program Header", caller
      end

      self.struct = program_header
    end

  end

end
end
end
