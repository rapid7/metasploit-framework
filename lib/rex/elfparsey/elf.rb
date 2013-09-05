#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/elfparsey/elfbase'
require 'rex/elfparsey/exceptions'
require 'rex/image_source'

module Rex
module ElfParsey
class Elf < ElfBase

  attr_accessor :elf_header, :program_header, :base_addr, :isource

  def initialize(isource)
    offset = 0
    base_addr = 0

    # ELF Header
    elf_header = ElfHeader.new(isource.read(offset, ELF_HEADER_SIZE))

    # Data encoding
    ei_data = elf_header.e_ident[EI_DATA,1].unpack("C")[0]

    e_phoff = elf_header.e_phoff
    e_phentsize = elf_header.e_phentsize
    e_phnum = elf_header.e_phnum

    # Program Header Table
    program_header = []

    e_phnum.times do |i|
      offset = e_phoff + (e_phentsize * i)

      program_header << ProgramHeader.new(
        isource.read(offset, PROGRAM_HEADER_SIZE), ei_data
      )

      if program_header[-1].p_type == PT_LOAD && base_addr == 0
        base_addr = program_header[-1].p_vaddr
      end

    end

    self.elf_header = elf_header
    self.program_header = program_header
    self.base_addr = base_addr
    self.isource = isource
  end

  def self.new_from_file(filename, disk_backed = false)

    file = ::File.new(filename)
    # file.binmode # windows... :\

    if disk_backed
      return self.new(ImageSource::Disk.new(file))
    else
      obj = new_from_string(file.read)
      file.close
      return obj
    end
  end

  def self.new_from_string(data)
    return self.new(ImageSource::Memory.new(data))
  end

  #
  # Returns true if this binary is for a 64-bit architecture.
  #
  def ptr_64?
    unless [ ELFCLASS32, ELFCLASS64 ].include?(
    elf_header.e_ident[EI_CLASS,1].unpack("C*")[0])
      raise ElfHeaderError, 'Invalid class', caller
    end

    elf_header.e_ident[EI_CLASS,1].unpack("C*")[0] == ELFCLASS64
  end

  #
  # Returns true if this binary is for a 32-bit architecture.
  # This check does not take into account 16-bit binaries at the moment.
  #
  def ptr_32?
    ptr_64? == false
  end

  #
  # Converts a virtual address to a string representation based on the
  # underlying architecture.
  #
  def ptr_s(rva)
    (ptr_32?) ? ("0x%.8x" % rva) : ("0x%.16x" % rva)
  end

  def offset_to_rva(offset)
    base_addr + offset
  end

  def rva_to_offset(rva)
    rva - base_addr
  end

  def read(offset, len)
    isource.read(offset, len)
  end

  def read_rva(rva, len)
    isource.read(rva_to_offset(rva), len)
  end

  def index(*args)
    isource.index(*args)
  end

  def close
    isource.close
  end

end
end
end
