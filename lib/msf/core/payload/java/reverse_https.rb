# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/java/reverse_http'

module Msf

###
#
# Complex payload generation for Java that speaks HTTPS
#
###

module Payload::Java::ReverseHttps

  include Msf::Payload::Java::ReverseHttp

  #
  # Generate the transport-specific configuration
  #
  def transport_config(opts={})
    transport_config_reverse_https(opts)
  end

  #
  # Override the scheme so that it has https instead of http
  #
  def scheme
    'https'
  end

  #
  # Override class_files to include the trust manager
  #
  def class_files
    [
      ["metasploit", "PayloadTrustManager.class"]
    ]
  end
end
end
