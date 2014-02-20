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
  # Initializes the packet parser context with an optional cipher.
  #
  def initialize(cipher = nil)
    self.cipher = cipher

    reset
  end

  #
  # Resets the parser state so that a new packet can begin being parsed.
  #
  def reset
    self.raw = ''
    self.hdr_length_left = 8
    self.payload_length_left = 0
  end

  #
  # Reads data from the wire and parse as much of the packet as possible.
  #
  def recv(sock)
    if (self.hdr_length_left > 0)
      buf = sock.read(self.hdr_length_left)

      if (buf)
        self.raw << buf

        self.hdr_length_left -= buf.length
      else
        raise EOFError
      end

      # If we've finished reading the header, set the
      # payload length left to the number of bytes
      # specified in the length
      if (self.hdr_length_left == 0)
        self.payload_length_left = raw.unpack("N")[0] - 8
      end
    elsif (self.payload_length_left > 0)
      buf = sock.read(self.payload_length_left)

      if (buf)
        self.raw << buf

        self.payload_length_left -= buf.length
      else
        raise EOFError
      end
    end

    # If we've finished reading the entire packet
    if ((self.hdr_length_left == 0) &&
        (self.payload_length_left == 0))

      # Create a typeless packet
      packet = Packet.new(0)

      # TODO: cipher decryption
      if (cipher)
      end

      # Serialize the packet from the raw buffer
      packet.from_r(self.raw)

      # Reset our state
      reset

      return packet
    end
  end

protected
  attr_accessor :cipher, :raw, :hdr_length_left, :payload_length_left  # :nodoc:

end


end; end; end

