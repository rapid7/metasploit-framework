# -*- coding: binary -*-

require 'rex/machparsey/machbase'
require 'rex/machparsey/exceptions'
require 'rex/image_source'

module Rex
module MachParsey


class Mach < MachBase
  attr_accessor :mach_header, :segments, :isource, :bits, :endian, :arch, :fat_offset

  def initialize(isource, offset = 0, fat = false)
    _parse_mach_header(isource, offset)
    if fat == true
      self.fat_offset = offset
    else
      self.fat_offset = 0
    end

    self.isource = isource
  end

  def _parse_mach_header(isource, offset)
    self.mach_header = MachHeader.new(isource.read(offset, MACH_HEADER_SIZE_64))
    bits = mach_header.bits
    endian = mach_header.endian
    ncmds = mach_header.ncmds

    if bits == BITS_32
      offset += MACH_HEADER_SIZE
    else
      offset += MACH_HEADER_SIZE_64
    end


    segments = []
    ncmds.times do
      load_command = LoadCommand.new(isource.read(offset, LOAD_COMMAND_SIZE), endian)

      case load_command.cmd
        when LC_SEGMENT
          segments << Segment.new(isource.read(offset, SEGMENT_COMMAND_SIZE), bits, endian)
        when LC_SEGMENT_64
          segments << Segment.new(isource.read(offset, SEGMENT_COMMAND_SIZE_64), bits, endian)
      end

      offset += load_command.cmdsize
    end

    self.mach_header = mach_header
    self.segments = segments
    self.isource = isource
    self.bits = bits
    self.endian = endian

    return segments
  end

  def self.new_from_file(filename, disk_backed = false)

    file = ::File.open(filename, "rb")

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

  def ptr_64?
    mach_header.bits == BITS_64
  end

  def ptr_32?
    ptr_64? == false
  end

  def ptr_s(vaddr)
    (ptr_32?) ? ("0x%.8x" % vaddr) : ("0x%.16x" % vaddr)
  end

  def read(offset, len)
    isource.read(fat_offset + offset, len)
  end

  def index(*args)
    isource.index(*args)
  end

  def close
    isource.close
  end

end

class Fat < FatBase
  attr_accessor :fat_header, :fat_archs, :machos, :isource

  def initialize(isource, offset = 0)
    self.fat_archs = []
    self.machos = []
    self.isource = isource
    self.fat_header = FatHeader.new(isource.read(offset, FAT_HEADER_SIZE))

    if !self.fat_header
      raise FatHeaderError, "Could not parse FAT header"
    end

    print "Detected " +  self.fat_header.nfat_arch.to_s +  " archs in binary.\n"

    offset += FAT_HEADER_SIZE

    self.fat_header.nfat_arch.times do
      fat_arch = FatArch.new(isource.read(offset, FAT_ARCH_SIZE), self.fat_header.endian)
      self.fat_archs << fat_arch
      self.machos << Mach.new(isource, fat_arch.offset, true)
      offset += FAT_ARCH_SIZE
    end


  end

  #this is useful for debugging but we don't use it for anything.
  def _parse_fat_header(isource, offset)
    archs = []
    nfat_arch = self.fat_header.nfat_arch

    print "Number of archs in binary: " + nfat_arch.to_s + "\n"

    nfat_arch.times do
      arch = FatArch.new(isource.read(offset, FAT_ARCH_SIZE), self.endian)

      case arch.cpu_type

      when CPU_TYPE_I386
        print "i386\n"

      when CPU_TYPE_X86_64
        print "x86_64\n"

      when CPU_TYPE_ARM
        print "Arm\n"

      when CPU_TYPE_POWERPC
        print "Power PC\n"

      when CPU_TYPE_POWERPC64
        print "Power PC 64\n"
      end

      offset += FAT_ARCH_SIZE
    end
  end

  def self.new_from_file(filename, disk_backed = false)

    file = ::File.open(filename, "rb")

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

  def ptr_64?
    mach_header.bits == BITS_64
  end

  def ptr_32?
    ptr_64? == false
  end

  def ptr_s(vaddr)
    (ptr_32?) ? ("0x%.8x" % vaddr) : ("0x%.16x" % vaddr)
  end

  def read(offset, len)
    isource.read(offset, len)
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
