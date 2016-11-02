
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

  #
  # Register reverse_http specific options
  #
  def initialize(*args)
    super
    # We don't need options here at all. All options are read on the fly from the
    # JSON file when a new connection comes in.
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

