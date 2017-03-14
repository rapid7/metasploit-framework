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

  # 4 byte xor
  # 4 byte length
  # 4 byte type
  HEADER_SIZE = 12

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
    self.hdr_length_left = HEADER_SIZE
    self.payload_length_left = 0
  end

  #
  # Reads data from the wire and parse as much of the packet as possible.
  #
  def recv(sock)
    # Create a typeless packet
    packet = Packet.new(0)

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
        xor_key = raw[0, 4].unpack('N')[0]
        length_bytes = packet.xor_bytes(xor_key, raw[4, 4])
        # header size doesn't include the xor key, which is always tacked on the front
        self.payload_length_left = length_bytes.unpack("N")[0] - (HEADER_SIZE - 4)
      end
    end
    if (self.payload_length_left > 0)
      buf = sock.read(self.payload_length_left)

      if (buf)
        self.raw << buf

        self.payload_length_left -= buf.length
      else
        raise EOFError
      end
    end

    in_progress = true

    # TODO: cipher decryption
    if (cipher)
    end

    # Deserialize the packet from the raw buffer
    packet.from_r(self.raw)

    # If we've finished reading the entire packet
    if ((self.hdr_length_left == 0) &&
        (self.payload_length_left == 0))

      # Reset our state
      reset

      # packet is complete!
      in_progress = false
    end

    return packet, in_progress
  end

protected
  attr_accessor :cipher, :raw, :hdr_length_left, :payload_length_left  # :nodoc:

end


end; end; end

