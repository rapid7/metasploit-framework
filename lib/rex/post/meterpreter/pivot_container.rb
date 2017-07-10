
# -*- coding: binary -*-

require 'rex/post/meterpreter/inbound_packet_handler'

module Rex
module Post
module Meterpreter

class PivotContainer

  # Class modifications to support global pivot message
  # dispatching without having to register a per-instance handler
  class << self
    include Rex::Post::Meterpreter::InboundPacketHandler

    # Class request handler for all channels that dispatches requests
    # to the appropriate class instance's DIO handler
    def request_handler(client, packet)
      if packet.method == 'core_pivot_new'
        STDERR.puts("Received pivot packet! #{packet.inspect}\n")
      end
      true
    end
  end

  def initialize(client)
    self.client = client
  end

  #
  # The associated meterpreter client instance
  #
  attr_accessor :client

protected

  #
  # Cleans up any lingering resources
  #
  def cleanup
  end

end

end; end; end

