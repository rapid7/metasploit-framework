# -*- coding: binary -*-

module Rex
module Post
module Meterpreter

###
#
# Mixin that provides stubs for handling inbound packets
#
###
module InboundPacketHandler

  #
  # Stub request handler that returns false by default.
  #
  def request_handler(client, packet)
    return false
  end

  #
  # Stub response handler that returns false by default.
  #
  def response_handler(client, packet)
    return false
  end

end

end; end; end
