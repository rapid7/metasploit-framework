# -*- coding: binary -*-
require 'rex/io/stream_abstraction'
require 'rex/sync/ref'

module Msf
module Handler

###
#
# This handler implements the HTTP SSL tunneling interface.
#
###
module ReverseHttps

  include Msf::Handler::Reverse::SSL
  include Msf::Handler::ReverseHttp

  #
  # Returns the string representation of the handler type
  #
  def self.handler_type
    return "reverse_https"
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
        OptPort.new('LPORT', [ true, "The local listener port", 8443 ]),
      ], Msf::Handler::ReverseHttps)

    register_advanced_options(
      [
        OptBool.new('StagerVerifySSLCert', [false, "Whether to verify the SSL certificate in Meterpreter"])
      ], Msf::Handler::ReverseHttps)

  end

end

end
end

