# -*- coding: binary -*-
module PacketFu
  # Implements the Explict Congestion Notification for TCPHeader.
  #
  # ==== Header Definition
  #
  #
  #  Integer(1 bit)  :n
  #  Integer(1 bit)  :c
  #  Integer(1 bit)  :e
  class TcpEcn < Struct.new(:n, :c, :e)

    include StructFu

    def initialize(args={})
      super(args[:n], args[:c], args[:e]) if args
    end

    # Returns the TcpEcn field as an integer... even though it's going
    # to be split across a byte boundary.
    def to_i
      (n.to_i << 2) + (c.to_i << 1) + e.to_i
    end

    # Reads a string to populate the object.
    def read(str)
      force_binary(str)
      return self if str.nil? || str.size < 2
      if 1.respond_to? :ord
        byte1 = str[0].ord
        byte2 = str[1].ord
      else
        byte1 = str[0]
        byte2 = str[1]
      end
      self[:n] = byte1 & 0b00000001 == 0b00000001 ? 1 : 0
      self[:c] = byte2 & 0b10000000 == 0b10000000 ? 1 : 0
      self[:e] = byte2 & 0b01000000 == 0b01000000 ? 1 : 0
      self
    end

  end
end
