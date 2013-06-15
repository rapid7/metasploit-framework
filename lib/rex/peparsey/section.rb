#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/peparsey/exceptions'
require 'rex/peparsey/pebase'
require 'rex/struct2'

module Rex
module PeParsey
class Section
	attr_accessor :_section_header, :_isource
	attr_accessor :base_rva

	#
	# Initialize a section.
	#
	#  isource        - The ImageSource class backing the image
	#  base_vma       - The address of this section base
	#  section_header - The section header (struct2) although this is not
	#    required, which is why there is a base_vma.  This can be nil.
	#
	def initialize(isource, base_rva, section_header = nil)
		self._isource        = isource
		self.base_rva        = base_rva
		self._section_header = section_header
	end

	def file_offset
		_isource.file_offset
	end

	def size
		_isource.size
	end

	def name
		# a section header is not required
		return nil if !_section_header

		# FIXME make this better...
		_section_header.v['Name'].gsub(/\x00+$/, '')
	end

	def flags
		# a section header is not required
		return nil if !_section_header
		_section_header.v['Characteristics']
	end

	def vma
		# a section header is not required
		return nil if !_section_header
		_section_header.v['VirtualAddress']
	end

	def raw_size
		# a section header is not required
		return nil if !_section_header
		_section_header.v['SizeOfRawData']
	end

	def _check_offset(offset, len = 1)
		if offset < 0 || offset+len > size
			raise BoundsError, "Offset #{offset} outside of section", caller
		end
	end

	def read(offset, len)
		_check_offset(offset, len)
		return _isource.read(offset, len)
	end

	def read_rva(rva, len)
		return read(rva_to_offset(rva), len)
	end

	def read_asciiz(offset)
		_check_offset(offset)
		return _isource.read_asciiz(offset)
	end

	def read_asciiz_rva(rva)
		return read_asciiz(rva_to_offset(rva))
	end

	def index(*args)
		_isource.index(*args)
	end

	def offset_to_rva(offset)
		if !contains_offset?(offset)
			raise BoundsError, "Offset #{offset} outside of section", caller
		end

		return offset + base_rva
	end

	def file_offset_to_rva(foffset)
		return offset_to_rva(foffset - file_offset)
	end

	def rva_to_offset(rva)
		offset = rva - base_rva
		if !contains_offset?(offset)
			raise BoundsError, "RVA #{rva} outside of section", caller
		end

		return offset
	end

	def rva_to_file_offset(rva)
		return rva_to_offset(rva) + file_offset
	end

	def contains_offset?(offset)
		offset >= 0 && offset < size
	end

	def contains_file_offset?(foffset)
		contains_offset?(foffset - file_offset)
	end

	def contains_rva?(rva)
		contains_offset?(rva - base_rva)
	end

end

end end
