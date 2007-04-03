#!/usr/bin/env ruby

require 'rex/peparsey/pebase'
require 'rex/peparsey/exceptions'

require 'rex/peparsey/image_source'
require 'rex/peparsey/section'

require 'rex/struct2'

#
# This class is for use with memdump.exe generated dump images.  It basically
# just lies, gets the ImageBase from the file name, and generates 1 big
# header_section with all of the data in it...
#

module Rex
module PeParsey
class PeMemDump < PeBase

	def self.new_from_string(data)
		raise NotImplementError
	end

	def self.new_from_file(filename, disk_backed = false)
		if filename[-4, 4] != '.rng'
			raise "Not a .rng file: #{filename}"
		end

		file = File.open(filename, 'rb')

		if disk_backed
			obj = ImageSource::Disk.new(file)
		else
			obj = ImageSource::Memory.new(file.read)
			obj.close
		end

		return self.new(obj, filename[0, 8].hex)
	end

	def initialize(isource, base)

		self._isource = isource
		self.header_section = Section.new(isource, base, nil)
		self.sections = [ ]

	end


end end end

