#!/usr/bin/env ruby

require 'rex/peparsey/pebase'
require 'rex/peparsey/exceptions'

require 'rex/peparsey/image_source'
require 'rex/peparsey/section'

require 'rex/struct2'

module Rex
module PeParsey
class Pe < PeBase

	def initialize(isource)

		#
		# DOS Header
		#
		# Parse the initial dos header, starting at the file beginning
		#
		offset = 0
		dos_header = self.class._parse_dos_header(isource.read(offset, IMAGE_DOS_HEADER_SIZE))

		#
		# File Header
		#
		# If there is going to be a PE, the dos header tells us where to find it
		# So now we try to parse the file (pe) header
		#
		offset += dos_header.e_lfanew

		# most likely an invalid e_lfanew...
		if offset > isource.size
			raise FileHeaderError, "e_lfanew looks invalid", caller
		end

		file_header = self.class._parse_file_header(isource.read(offset, IMAGE_FILE_HEADER_SIZE)) 

		#
		# Optional Header
		#
		# After the file header, we find the optional header.  Right now
		# we require a optional header.  Despite it's name, all binaries
		# that we are interested in should have one.  We need this
		# header for a lot of stuff, so we die without it...
		#
		offset += IMAGE_FILE_HEADER_SIZE
		optional_header = self.class._parse_optional_header(
		  isource.read(offset, file_header.SizeOfOptionalHeader)
		)

		if !optional_header
			raise OptionalHeaderError, "No optional header!", caller
		end

		base = optional_header.ImageBase

		#
		# Section Headers
		#
		# After the optional header should be the section headers.
		# We know how many there should be from the file header...
		#
		offset += file_header.SizeOfOptionalHeader

		num_sections = file_header.NumberOfSections
		section_headers = self.class._parse_section_headers(
		  isource.read(offset, IMAGE_SIZEOF_SECTION_HEADER * num_sections)
		)

		#
		# End of Headers
		#
		# After the section headers (which are padded to FileAlignment)
		# we should find the section data, described by the section
		# headers...
		#
		# So this is the end of our header data, lets store this
		# in an image source for possible access later...
		#
		offset += IMAGE_SIZEOF_SECTION_HEADER * num_sections
		offset = self.class._align_offset(offset, optional_header.FileAlignment)

		header_section = Section.new(isource.subsource(0, offset), 0, nil)

		#
		# Sections
		#
		# So from here on out should be section data, and then any
		# trailing data (like authenticode and stuff I think)
		#

		sections = [ ]

		section_headers.each do |section_header|

			rva         = section_header.VirtualAddress
			size        = section_header.SizeOfRawData
			file_offset = section_header.PointerToRawData

			sections << Section.new(
			  isource.subsource(file_offset, size),
			  rva,
			  section_header
			)
		end


		#
		# Save the stuffs!
		#
		# We have parsed enough to load the file up here, now we just
		# save off all of the structures and data... We will
		# save our fake header section, the real sections, etc.
		#

		#
		# You shouldn't need to access these!
		#

		self._isource          = isource

		self._dos_header       = dos_header
		self._file_header      = file_header
		self._optional_header  = optional_header
		self._section_headers  = section_headers

		self.image_base        = base
		self.sections          = sections
		self.header_section    = header_section

	end

	#
	# Return everything that's going to be mapped in the process
	# and accessable.  This should include all of the sections
	# and our "fake" section for the header data...
	#
	def all_sections
		[ header_section ] + sections
	end


end end end

