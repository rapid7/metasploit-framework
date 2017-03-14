# -*- coding: binary -*-

require 'msf/core/payload/uuid/options'

##
# This module contains helper functions for creating the transport
# configuration stubs that are used for Meterpreter payloads.
##
module Msf::Payload::TransportConfig

  include Msf::Payload::UUID::Options

  def transport_config_reverse_tcp(opts={})
    config = transport_config_bind_tcp(opts)
    config[:lhost] = datastore['LHOST']
    config
  end

  def transport_config_reverse_ipv6_tcp(opts={})
    config = transport_config_reverse_tcp(opts)
    config[:scheme] = 'tcp6'
    config[:scope_id] = datastore['SCOPEID']
    config
  end

  def transport_config_bind_tcp(opts={})
    {
      scheme: 'tcp',
      lhost:  datastore['LHOST'],
      lport:  datastore['LPORT'].to_i
    }.merge(timeout_config)
  end

  def transport_config_reverse_https(opts={})
    config = transport_config_reverse_http(opts)
    config[:scheme] = datastore['OverrideScheme'] || 'https'
    config[:ssl_cert_hash] = get_ssl_cert_hash(datastore['StagerVerifySSLCert'],
                                               datastore['HandlerSSLCert'])
    config
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

    {
      scheme:      datastore['OverrideScheme'] || 'http',
      lhost:       opts[:lhost] || datastore['LHOST'],
      lport:       (opts[:lport] || datastore['LPORT']).to_i,
      uri:         uri,
      ua:          datastore['MeterpreterUserAgent'],
      proxy_host:  datastore['PayloadProxyHost'],
      proxy_port:  datastore['PayloadProxyPort'],
      proxy_type:  datastore['PayloadProxyType'],
      proxy_user:  datastore['PayloadProxyUser'],
      proxy_pass:  datastore['PayloadProxyPass']
    }.merge(timeout_config)
  end

private

  def timeout_config
    {
      comm_timeout: datastore['SessionCommunicationTimeout'].to_i,
      retry_total:  datastore['SessionRetryTotal'].to_i,
      retry_wait:   datastore['SessionRetryWait'].to_i
    }
  end

end
