# -*- coding: binary -*-
require 'rex/io/stream_abstraction'
require 'rex/sync/ref'
require 'msf/core/handler/reverse_http'

module Msf
module Handler

###
#
# This handler implements the HTTP SSL tunneling interface.
#
###
module ReverseHttpsProxy

  include Msf::Handler::ReverseHttp

  #
  # Returns the string representation of the handler type
  #
  def self.handler_type
    return "reverse_https_proxy"
  end

  #
  # Returns the connection-described general handler type, in this case
  # 'tunnel'.
  #
  def self.general_handler_type
    "tunnel"
  end

  #
  # Initializes the HTTP SSL tunneling handler.
  #
  def initialize(info = {})
    super

    register_options(
      [
        OptAddressLocal.new('LHOST', "The local listener hostname", default: "127.0.0.1"),
        OptPort.new('LPORT', "The local listener port", default: 8443),
        OptString.new('HttpProxyHost', "The proxy server's IP address", required: true, default: "127.0.0.1", aliases: ['PayloadProxyHost']),
        OptPort.new('HttpProxyPort', "The proxy port to connect to", required: true, default: 8080, aliases: ['PayloadProxyPort']),
        OptEnum.new('HttpProxyType', 'The proxy type, HTTP or SOCKS', enums: ['HTTP', 'SOCKS'], aliases: ['PayloadProxyType']),
        OptString.new('HttpProxyUser', "An optional username for HTTP proxy authentication", aliases: ['PayloadProxyUser']),
        OptString.new('HttpProxyPass', "An optional password for HTTP proxy authentication", aliases: ['PayloadProxyPass'])
      ], Msf::Handler::ReverseHttpsProxy)

    register_advanced_options(
      [
        OptAddress.new('ReverseListenerBindAddress', [ false, 'The specific IP address to bind to on the local system']),
        OptInt.new('ReverseListenerBindPort', [ false, 'The port to bind to on the local system if different from LPORT' ])
      ], Msf::Handler::ReverseHttpsProxy)

  end

end

end
end

