# -*- coding: binary -*-

module Rex
module Post
module Meterpreter

###
#
# This class is responsible for reading in and decrypting meterpreter
# packets that arrive on a socket
#
###
class PacketParser

  #
  # Initializes the packet parser context.
  #
  def initialize
    reset
  end

  #
  # Resets the parser state so that a new packet can begin being parsed.
  #
  def reset
    self.packet = Packet.new(0)
  end

  #
  # Reads data from the wire and parse as much of the packet as possible.
  #
  def recv(sock)
    bytes_left = self.packet.raw_bytes_required

    if bytes_left > 0
      raw = sock.read(bytes_left)
      if raw
        self.packet.add_raw(raw)
      else
        raise EOFError
      end
    end

    if self.packet.raw_bytes_required == 0
      packet = self.packet
      reset
      return packet
    end

    nil
  end

protected
  attr_accessor :cipher, :packet    # :nodoc:

end


end; end; end

