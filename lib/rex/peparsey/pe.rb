# -*- coding: binary -*-

require 'rex/image_source'
require 'rex/peparsey/exceptions'
require 'rex/peparsey/pebase'
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
    # These should not be accessed directly
    #

    self._isource          = isource

    self._dos_header       = dos_header
    self._file_header      = file_header
    self._optional_header  = optional_header
    self._section_headers  = section_headers

    self.image_base        = base
    self.sections          = sections
    self.header_section    = header_section

    self._config_header    = _parse_config_header()
    self._tls_header       = _parse_tls_header()

    # These can be accessed directly
    self.hdr               = HeaderAccessor.new
    self.hdr.dos           = self._dos_header
    self.hdr.file          = self._file_header
    self.hdr.opt           = self._optional_header
    self.hdr.sections      = self._section_headers
    self.hdr.config        = self._config_header
    self.hdr.tls           = self._tls_header
    self.hdr.exceptions    = self._exception_header

    # We load the exception directory last as it relies on hdr.file to be created above.
    self._exception_header = _load_exception_directory()
  end

  #
  # Return everything that's going to be mapped in the process
  # and accessable.  This should include all of the sections
  # and our "fake" section for the header data...
  #
  def all_sections
    [ header_section ] + sections
  end

  #
  # Returns true if this binary is for a 64-bit architecture.
  #
  def ptr_64?
    [
      IMAGE_FILE_MACHINE_IA64,
      IMAGE_FILE_MACHINE_ALPHA64,
      IMAGE_FILE_MACHINE_AMD64
    ].include?(self._file_header.Machine)
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
  def ptr_s(va)
    (ptr_32?) ? ("0x%.8x" % va) : ("0x%.16x" % va)
  end

  #
  # Converts a file offset into a virtual address
  #
  def file_offset_to_va(offset)
    image_base + file_offset_to_rva(offset)
  end

  #
  # Read raw bytes from the specified offset in the underlying file
  #
  # NOTE: You should pass raw file offsets into this, not offsets from
  # the beginning of the section. If you need to read from within a
  # section, add section.file_offset prior to passing the offset in.
  #
  def read(offset, len)
    _isource.read(offset, len)
  end

  def size
    _isource.size
  end
  def length
    _isource.size
  end

end end end
