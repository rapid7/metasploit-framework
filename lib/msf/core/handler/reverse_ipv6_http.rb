# -*- coding: binary -*-
require 'msf/core/handler/reverse_http'

module Msf
module Handler

###
#
# This handler implements the HTTP tunneling interface.
#
###
module ReverseIPv6Http

  include Msf::Handler::ReverseHttp

  #
  # Override the handler_type to indicate IPv6 mode
  #
  def self.handler_type
    return "reverse_ipv6_http"
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

