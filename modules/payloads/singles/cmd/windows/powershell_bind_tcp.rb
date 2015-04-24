##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/find_shell'
require 'msf/base/sessions/powershell'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  CachedSize = 0

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Windows Command, Interact with Established Connection',
      'Description'   => 'Interacts with a shell on an established socket connection',
      'Author'        => 'hdm',
      'License'       => MSF_LICENSE,
      'Platform'      => 'windows',
      'Arch'          => ARCH_CMD,
      'Handler'       => Msf::Handler::BindTcp,
      'Session'       => Msf::Sessions::PowerShell,
      'PayloadType'   => 'cmd_interact',
      'RequiredCmd'   => 'generic',
      'Payload'       =>
        {
          'Offsets' => { },
          'Payload' => ''
        }
      ))
  end

end
