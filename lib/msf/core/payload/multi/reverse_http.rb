
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
    #register_advanced_options([
    #    OptInt.new('StagerURILength', [false, 'The URI length for the stager (at least 5 bytes)']),
    #    OptInt.new('StagerRetryCount', [false, 'The number of times the stager should retry if the first connect fails', 10]),
    #    OptString.new('PayloadProxyHost', [false, 'An optional proxy server IP address or hostname']),
    #    OptPort.new('PayloadProxyPort', [false, 'An optional proxy server port']),
    #    OptString.new('PayloadProxyUser', [false, 'An optional proxy server username']),
    #    OptString.new('PayloadProxyPass', [false, 'An optional proxy server password']),
    #    OptEnum.new('PayloadProxyType', [false, 'The type of HTTP proxy (HTTP or SOCKS)', 'HTTP', ['HTTP', 'SOCKS']])
    #  ], self.class)
  end

  #
  # Generate the first stage
  #
  def generate(opts={})
    # TODO: read the JSON file and find the configurat for the given UUID
    # TODO: map the JSON file content to a stager
    # TODO: create an instance of a stager
    # TODO: map the JSON content to a datastore
    # TODO: invoke the stager with the given datastore.
    ''
  end

  #
  # Generate the transport-specific configuration
  #
  def transport_config(opts={})
    # TODO: get the transport configuration from the payload as well.
    ''
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

