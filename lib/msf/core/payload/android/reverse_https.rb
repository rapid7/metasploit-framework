# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/android/reverse_http'

module Msf

###
#
# Complex payload generation for Android that speaks HTTPS
#
###

module Payload::Android::ReverseHttps

  include Msf::Payload::Android::ReverseHttp

  #
  # Generate the transport-specific configuration
  #
  def transport_config(opts={})
    transport_config_reverse_https(opts)
  end

end
end

