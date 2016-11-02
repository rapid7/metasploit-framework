# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'
require 'msf/core/payload/multi/reverse_http'

module Msf

###
#
# Complex payload generation for arch-agnostic HTTP.
#
###

module Payload::Multi::ReverseHttps

  include Msf::Payload::TransportConfig
  include Msf::Payload::Multi::ReverseHttp

  #
  # Generate the first stage
  #
  def generate(opts={})
    opts[:ssl] = true
    super(opts)
  end

end

end

