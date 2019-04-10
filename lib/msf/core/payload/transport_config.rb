# -*- coding: binary -*-

require 'msf/core/payload/uuid/options'
require 'msf/core/payload/pingback/options'

##
# This module contains helper functions for creating the transport
# configuration stubs that are used for Meterpreter payloads.
##
module Msf::Payload::TransportConfig

  include Msf::Payload::Pingback::Options
  include Msf::Payload::UUID::Options

  def transport_config_reverse_tcp(opts={})
    ds = opts[:datastore] || datastore
    config = transport_config_bind_tcp(opts)
    config[:lhost] = ds['LHOST']
    config
  end

  def transport_config_reverse_udp(opts={})
    config =transport_config_reverse_tcp(opts)
    config[:scheme] = 'udp'
    config
  end

  def transport_config_reverse_ipv6_tcp(opts={})
    ds = opts[:datastore] || datastore
    config = transport_config_reverse_tcp(opts)
    config[:scheme] = 'tcp6'
    config[:scope_id] = ds['SCOPEID']
    config
  end

  def transport_config_bind_tcp(opts={})
    ds = opts[:datastore] || datastore
    {
      scheme: 'tcp',
      lhost:  ds['LHOST'],
      lport:  ds['LPORT'].to_i
    }.merge(timeout_config(opts))
  end

  def transport_config_reverse_https(opts={})
    ds = opts[:datastore] || datastore
    opts[:scheme] ||= 'https'
    config = transport_config_reverse_http(opts)
    config[:ssl_cert_hash] = get_ssl_cert_hash(ds['StagerVerifySSLCert'],
                                               ds['HandlerSSLCert'])
    config
  end

  def transport_uri_components(opts={})
    ds = opts[:datastore] || datastore
    if opts[:url]
      u = URI(opts[:url])
      scheme = u.scheme
      lhost = u.host
      lport = u.port
    else
      scheme = opts[:scheme]
      lhost = ds['LHOST']
      lport = ds['LPORT']
    end
    if ds['OverrideRequestHost']
      scheme = ds['OverrideScheme'] || scheme
      lhost = ds['OverrideLHOST'] || lhost
      lport = ds['OverrideLPORT'] || lport
    end
    [scheme, lhost, lport]
  end

  def transport_config_reverse_http(opts={})
    # most cases we'll have a URI already, but in case we don't
    # we should ask for a connect to happen given that this is
    # going up as part of the stage.
    uri = opts[:uri]
    unless uri
      type = opts[:stageless] == true ? :init_connect : :connect
      sum = uri_checksum_lookup(type)
      uri = luri + generate_uri_uuid(sum, opts[:uuid])
    end

    ds = opts[:datastore] || datastore
    opts[:scheme] ||= 'http'
    scheme, lhost, lport = transport_uri_components(opts)

    {
      scheme:          scheme,
      lhost:           lhost,
      lport:           lport.to_i,
      uri:             uri,
      ua:              ds['HttpUserAgent'],
      proxy_host:      ds['HttpProxyHost'],
      proxy_port:      ds['HttpProxyPort'],
      proxy_type:      ds['HttpProxyType'],
      proxy_user:      ds['HttpProxyUser'],
      proxy_pass:      ds['HttpProxyPass'],
      host:            ds['HttpHostHeader'],
      cookie:          ds['HttpCookie'],
      referer:         ds['HttpReferer'],
      custom_headers:  get_custom_headers(ds)
    }.merge(timeout_config(opts))
  end

  def transport_config_reverse_named_pipe(opts={})
    ds = opts[:datastore] || datastore
    {
      scheme: 'pipe',
      lhost:  ds[:pipe_host] || ds['PIPEHOST'],
      uri:    "/#{ds[:pipe_host] || ds['PIPENAME']}"
    }.merge(timeout_config(opts))
  end

  def transport_config_bind_named_pipe(opts={})
    ds = opts[:datastore] || datastore
    {
      scheme:     'pipe',
      lhost:      '.',
      uri:        "/#{ds['PIPENAME']}",
    }.merge(timeout_config(opts))
    
  end


private

  def get_custom_headers(ds)
    headers = ""
    headers << "Host: #{ds['HttpHostHeader']}\r\n" if ds['HttpHostHeader']
    headers << "Cookie: #{ds['HttpCookie']}\r\n" if ds['HttpCookie']
    headers << "Referer: #{ds['HttpReferer']}\r\n" if ds['HttpReferer']

    if headers.length > 0
      headers
    else
      nil
    end
  end

  def timeout_config(opts={})
    ds = opts[:datastore] || datastore
    {
      comm_timeout: (ds[:comm_timeout] || ds['SessionCommunicationTimeout']).to_i,
      retry_total:  (ds[:retry_total] || ds['SessionRetryTotal']).to_i,
      retry_wait:   (ds[:retry_wait] || ds['SessionRetryWait']).to_i
    }
  end

end
