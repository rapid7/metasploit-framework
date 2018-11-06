# -*- coding: binary -*-
module PacketFu
  # Implements the Reserved bits for TCPHeader.
  #
  # ==== Header Definition
  #
  #
  #  Integer(1 bit)  :r1
  #  Integer(1 bit)  :r2
  #  Integer(1 bit)  :r3
  class TcpReserved < Struct.new(:r1, :r2, :r3)

    include StructFu

    def initialize(args={})
      super(
        args[:r1] || 0,
        args[:r2] || 0,
        args[:r3] || 0) if args.kind_of? Hash
    end

    # Returns the Reserved field as an integer.
    def to_i
      (r1.to_i << 2) + (r2.to_i << 1) + r3.to_i
    end

    # Reads a string to populate the object.
    def read(str)
      force_binary(str)
      return self if str.nil? || str.size.zero?
      if 1.respond_to? :ord
        byte = str[0].ord
      else
        byte = str[0]
      end
      self[:r1] = byte & 0b00000100 == 0b00000100 ? 1 : 0
      self[:r2] = byte & 0b00000010 == 0b00000010 ? 1 : 0
      self[:r3] = byte & 0b00000001 == 0b00000001 ? 1 : 0
      self
    end

  end
end
