# -*- coding: binary -*-
require 'msf/core/handler/reverse_http'
require 'msf/core/handler/reverse_https'

module Msf
module Handler

###
#
# This handler implements the HTTP SSL tunneling interface.
#
###
module ReverseIPv6Https

  include Msf::Handler::ReverseHttps

  #
  # Override the handler_type to indicate IPv6 mode
  #
  def self.handler_type
    return "reverse_ipv6_https"
  end

  #
  # Returns the connection-described general handler type, in this case
  # 'tunnel'.
  #
  def self.general_handler_type
    "tunnel"
  end

end
end
end

