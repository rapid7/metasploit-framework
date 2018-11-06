# -*- coding: binary -*-
module PacketFu
  # Implements the Header Length for TCPHeader.
  #
  # ==== Header Definition
  #
  #   Integer(4 bits)  :hlen
  class TcpHlen < Struct.new(:hlen)
    
    include StructFu

    def initialize(args={})
      super(args[:hlen])
    end

    # Returns the TcpHlen field as an integer. Note these will become the high
    # bits at the TCP header's offset, even though the lower 4 bits
    # will be further chopped up.
    def to_i
      hlen.to_i & 0b1111
    end

    # Reads a string to populate the object.
    def read(str)
      force_binary(str)
      return self if str.nil? || str.size.zero?
      if 1.respond_to? :ord
        self[:hlen] = (str[0].ord & 0b11110000) >> 4
      else
        self[:hlen] = (str[0] & 0b11110000) >> 4
      end
      self
    end

    # Returns the object in string form.
    def to_s
      [self.to_i].pack("C")
    end

  end
end
