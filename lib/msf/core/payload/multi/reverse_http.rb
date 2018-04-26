
# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/uuid/options'

module Msf

###
#
# Complex payload generation for arch-agnostic HTTP.
#
###

module Payload::Multi::ReverseHttp

  include Msf::Payload::UUID::Options
  include Msf::Payload::Multi

  #
  # Register reverse_http specific options
  #
  def initialize(*args)
    super
    register_advanced_options(
      [ OptInt.new('StagerURILength', 'The URI length for the stager (at least 5 bytes)') ] +
      Msf::Opt::stager_retry_options +
      Msf::Opt::http_header_options +
      Msf::Opt::http_proxy_options
    )
  end

  #
  # Generate the first stage
  #
  def generate(opts={})
    # Not such thing as a first stage for multi/reverse_http
    ''
  end

  #
  # Generate the transport-specific configuration
  #
  def transport_config(opts={})
    transport_config_reverse_http(opts)
  end


  #
  # Do not transmit the stage over the connection. We handle this via HTTPS
  #
  def stage_over_connection?
    false
  end

  #
  # Always wait at least 20 seconds for this payload (due to staging delays)
  #
  def wfs_delay
    20
  end

end

end
