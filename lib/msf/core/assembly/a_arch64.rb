# frozen_string_literal: true

require 'metasm'

module Msf
  module Assembly
    # Encodes the subset of AArch64 instructions needed by the framework.
    #
    # Metasm 1.0.6 cannot parse all required AArch64 assembly text, so this helper selects opcodes and
    # populates their encoded fields directly. These are Metasm internals and must be checked when
    # updating that dependency.
    module AArch64
      module_function

      # @param name [String] Metasm instruction name.
      # @param fields [Hash{Symbol => Integer}] Metasm opcode fields and values.
      # @return [String] Encoded little-endian instruction.
      def instruction(name, **fields)
        opcode = processor.opcode_list_byname.fetch(name).find do |candidate|
          candidate.args == fields.keys && !candidate.props[:r_32] && !candidate.props[:mem_incr]
        end
        raise Metasm::EncodeError, "Unsupported AArch64 instruction: #{name}" unless opcode

        word = fields.reduce(opcode.bin) do |encoded, (field, value)|
          mask, shift = opcode.fields.fetch(field)
          encoded | ((value & mask) << shift)
        end
        [word].pack('V')
      end

      # @param name [String] Metasm branch instruction name.
      # @param instruction_address [Integer] Address of the branch instruction.
      # @param destination [Integer] Address to branch to.
      # @param bits [Integer] Width of the signed immediate field.
      # @param field [Symbol] Metasm opcode field holding the immediate.
      # @param fields [Hash{Symbol => Integer}] Additional Metasm opcode fields and values.
      # @return [String] Encoded little-endian branch instruction.
      def branch(name, instruction_address:, destination:, bits: 19, field: :i19_5, **fields)
        displacement = destination - instruction_address
        raise RangeError, 'AArch64 branch destination is not instruction-aligned' unless (displacement % 4).zero?

        immediate = displacement / 4
        minimum = -(1 << (bits - 1))
        maximum = (1 << (bits - 1)) - 1
        raise RangeError, 'AArch64 branch destination is too far away' unless immediate.between?(minimum, maximum)

        instruction(name, **fields.merge(field => immediate))
      end

      # @param instruction_address [Integer] Address of the ADR instruction.
      # @param destination [Integer] Address to load.
      # @param register [Integer] Destination register number.
      # @return [String] Encoded little-endian ADR instruction.
      def adr(instruction_address:, destination:, register:)
        immediate = destination - instruction_address
        minimum = -(1 << 20)
        maximum = (1 << 20) - 1
        raise RangeError, 'AArch64 ADR destination is too far away' unless immediate.between?(minimum, maximum)

        encoded = ((immediate & 3) << 29) | (((immediate >> 2) & 0x7ffff) << 5)
        instruction('adr', rt: register, i19_5_2_29: encoded)
      end

      def processor
        @processor ||= Metasm::ARM64.new
      end
      private_class_method :processor
    end
  end
end
