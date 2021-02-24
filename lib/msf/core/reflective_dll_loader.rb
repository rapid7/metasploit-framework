# -*- coding: binary -*-

###
#
# This mixin contains functionality which loads a Reflective
# DLL from disk into memory and finds the offset of the
# reflective loader's entry point.
#
###

require 'rex/peparsey'

module Msf::ReflectiveDLLLoader

  # This is the ordinal of the reflective loader by default
  # In new RDI DLLs that come with MSF
  EXPORT_REFLECTIVELOADER = 1

  # Load a reflectively-injectable DLL from disk and find the offset
  # to the ReflectiveLoader function inside the DLL.
  #
  # @param [String] dll_path Path to the DLL to load.
  #
  # @return [Array] Tuple of DLL contents and offset to the
  #                 +ReflectiveLoader+ function within the DLL.
  def load_rdi_dll(dll_path, loader_name: 'ReflectiveLoader', loader_ordinal: EXPORT_REFLECTIVELOADER)
    dll = ''
    ::File.open(dll_path, 'rb') { |f| dll = f.read }

    offset = parse_pe(dll, loader_name: loader_name, loader_ordinal: loader_ordinal)

    unless offset
      raise "Cannot find the ReflectiveLoader entry point in #{dll_path}"
    end

    return dll, offset
  end

  # Load a reflectively-injectable DLL from a string and find the offset
  # to the ReflectiveLoader function inside the DLL.
  #
  # @param [String] dll_data the DLL data to load.
  #
  # @return [Integer] offset to the +ReflectiveLoader+ function within the DLL.
  def load_rdi_dll_from_data(dll_data, loader_name: 'ReflectiveLoader', loader_ordinal: EXPORT_REFLECTIVELOADER)
    offset = parse_pe(dll_data, loader_name: loader_name, loader_ordinal: loader_ordinal)

    unless offset
      raise 'Cannot find the ReflectiveLoader entry point in DLL data'
    end

    offset
  end

  private

  def parse_pe(dll, loader_name: 'ReflectiveLoader', loader_ordinal: EXPORT_REFLECTIVELOADER)
    pe = Rex::PeParsey::Pe.new(Rex::ImageSource::Memory.new(dll))
    offset = nil

    unless loader_name.nil?
      pe.exports.entries.each do |e|
        if e.name =~ /^\S*#{loader_name}\S*/
          offset = pe.rva_to_file_offset(e.rva)
          break
        end
      end
    end

    # If we aren't able to find the ReflectiveLoader, we need to
    # fallback to the known ordinal export for RDI DLLs?
    if offset.nil? && !loader_ordinal.nil?
      e = pe.exports.entries.find {|e| e.ordinal == loader_ordinal}
      offset = pe.rva_to_file_offset(e.rva)
    end

    offset
  end
end
