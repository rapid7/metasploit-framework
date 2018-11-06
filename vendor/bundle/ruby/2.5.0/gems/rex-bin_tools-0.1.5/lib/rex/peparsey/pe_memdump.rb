# -*- coding: binary -*-

require 'rex/image_source'
require 'rex/peparsey/exceptions'
require 'rex/peparsey/pebase'
require 'rex/peparsey/section'
require 'rex/struct2'

#
# This class is for use with memdump.exe generated dump images.  It basically
# just lies, gets the ImageBase from the file name, and generates 1 big
# header_section with all of the data in it...
#

module Rex
module PeParsey
class PeMemDump < Pe

  def self.new_from_string(data)
    raise NotImplementError
  end

  def self.new_from_file(filename, disk_backed = false)

    if filename[-4, 4] != '.rng'
      raise "Not a .rng file: #{filename}"
    end

    if filename[-9, 9] == "index.rng"
      raise SkipError
    end

    file = File.open(filename, 'rb')

    if disk_backed
      obj = ImageSource::Disk.new(file)
    else
      obj = ImageSource::Memory.new(file.read)
      obj.close
    end

    return self.new(obj, filename.gsub(/.*[\/\\]/, '')[0,8].hex)
  end

  def initialize(isource, base)
    self._isource = isource
    self.header_section = Section.new(isource, base, nil)
    self.sections = [ self.header_section ]
    self.image_base = 0
  end

  def all_sections
    self.sections
  end

  # No 64-bit support
  def ptr_64?
    false
  end

end end end
