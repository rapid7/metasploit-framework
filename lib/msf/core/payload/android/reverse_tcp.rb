# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'

module Msf

###
#
# Complex payload generation for Android that speaks TCP
#
###

module Payload::Android::ReverseTcp

  include Msf::Payload::TransportConfig
  include Msf::Payload::Android

  #
  # Generate the transport-specific configuration
  #
  def transport_config(opts={})
    transport_config_reverse_tcp(opts)
  end

end
end

