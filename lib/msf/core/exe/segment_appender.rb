# -*- coding: binary -*-

require 'rex/text'

module Msf
  module Exe
    # Appends payload bytes to a template as a new PE section.
    class SegmentAppender
      MAX_PE_SECTION_NAME_LENGTH = 8
      MAX_SECTION_NAME_WITHOUT_DOT_LENGTH = MAX_PE_SECTION_NAME_LENGTH - 1
      DEFAULT_SECTION_CHARACTERISTICS = %w[MEM_READ MEM_WRITE MEM_EXECUTE].freeze

      attr_accessor :payload, :template, :arch, :section_name, :section_characteristics

      def initialize(opts = {})
        @payload = opts[:payload]
        @template = opts[:template]
        @arch = opts[:arch] || :x86
        @section_name = opts.key?(:section_name) ? opts[:section_name] : opts[:secname]
        @section_characteristics = opts.fetch(:section_characteristics, DEFAULT_SECTION_CHARACTERISTICS).dup
      end

      # for backwards compatibility
      alias secname section_name
      alias secname= section_name=

      def processor
        case arch
        when :x86
          Metasm::Ia32.new
        when :x64
          Metasm::X86_64.new
        else
          raise 'Incompatible architecture'
        end
      end

      def generate_pe
        pe_orig = Metasm::PE.decode_file(template)
        pe = copy_pe(pe_orig)

        append_section(pe)
        pe.cpu = pe_orig.cpu

        pe.encode_string
      end

      def copy_pe(pe_orig)
        pe = pe_orig.mini_copy

        # Copy the headers and exports
        pe.mz.encoded = pe_orig.encoded[0, pe_orig.coff_offset - 4]
        pe.mz.encoded.export = pe_orig.encoded[0, 512].export.dup
        pe.header.time = pe_orig.header.time

        # Don't rebase if we can help it since Metasm doesn't do relocations well
        pe.optheader.dll_characts.delete('DYNAMIC_BASE')

        pe
      end

      def append_section(pe, prefix: '', default_name: nil)
        section = Metasm::PE::Section.new
        section.name = build_section_name(default_name)
        section.encoded = build_section_data(prefix: prefix)
        section.characteristics = section_characteristics

        pe.sections << section
        pe.invalidate_header

        section
      end

      def build_section_name(default_name = nil)
        requested_section_name = section_name
        normalized_section_name = if requested_section_name.blank?
                                    default_name || random_section_name
                                  elsif requested_section_name.start_with?('.')
                                    requested_section_name.downcase
                                  else
                                    '.' + requested_section_name.downcase
                                  end

        if normalized_section_name.bytesize > MAX_PE_SECTION_NAME_LENGTH
          raise ArgumentError,
                ":section_name must fit in the #{MAX_PE_SECTION_NAME_LENGTH}-byte PE section name field (#{MAX_SECTION_NAME_WITHOUT_DOT_LENGTH} bytes when the leading '.' is omitted)"
        end

        @section_name = normalized_section_name
      end

      def random_section_name
        '.' + Rex::Text.rand_text_alpha_lower(4)
      end

      private

      def build_section_data(prefix:)
        Metasm::EncodedData.new(payload)
      end
    end
  end
end
