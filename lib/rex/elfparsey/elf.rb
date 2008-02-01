#!/usr/bin/env ruby

# $Id$

require 'rex/elfparsey/elfbase'
require 'rex/elfparsey/exceptions'
require 'rex/elfparsey/image_source'

module Rex
module ElfParsey
class Elf < ElfBase

	attr_accessor :elf_header, :program_header, :base_addr, :isource

	def initialize(isource)
		offset = 0
		base_addr = 0

		# ELF Header
		elf_header = ElfHeader.new(isource.read(offset, ELF_HEADER_SIZE))

		ei_data = elf_header.e_ident[EI_DATA]
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

	# Stolen from lib/rex/peparsey/pebase.rb

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

	# Stolen from lib/rex/peparsey/pebase.rb

	def self.new_from_string(data)
		return self.new(ImageSource::Memory.new(data))
	end

	# Stolen from lib/rex/peparsey/pe.rb

	#
	# Converts a virtual address to a string representation based on the
	# underlying architecture.
	#
	def ptr_s(va)
		#(ptr_32?) ? ("0x%.8x" % va) : ("0x%.16x" % va)
		"0x%.8x" % va
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

	def close
		isource.close
	end

	def index(*args)
		isource.index(*args)
	end

end
end
end
