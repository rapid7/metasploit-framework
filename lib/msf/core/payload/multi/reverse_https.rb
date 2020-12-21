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
  # Generate the transport-specific configuration
  #
  def transport_config(opts={})
    transport_config_reverse_https(opts)
  end

end

end

