# -*- coding: binary -*-
module PacketFu
  # Implements flags for TCPHeader.
  #
  # ==== Header Definition
  #
  #  Integer(1 bit)  :urg
  #  Integer(1 bit)  :ack
  #  Integer(1 bit)  :psh
  #  Integer(1 bit)  :rst
  #  Integer(1 bit)  :syn
  #  Integer(1 bit)  :fin
  #
  # Flags can typically be set by setting them either to 1 or 0, or to true or false.
  class TcpFlags < Struct.new(:urg, :ack, :psh, :rst, :syn, :fin)

    include StructFu

    def initialize(args={})
      # This technique attemts to ensure that flags are always 0 (off)
      # or 1 (on). Statements like nil and false shouldn't be lurking in here.
      if args.nil? || args.size.zero?
        super( 0, 0, 0, 0, 0, 0)
      else
        super(
          (args[:urg] ? 1 : 0),
          (args[:ack] ? 1 : 0),
          (args[:psh] ? 1 : 0),
          (args[:rst] ? 1 : 0),
          (args[:syn] ? 1 : 0),
          (args[:fin] ? 1 : 0)
        )
      end
    end

    # Returns the TcpFlags as an integer.
    # Also not a great candidate for to_s due to the short bitspace.
    def to_i
      (urg.to_i << 5) + (ack.to_i << 4) + (psh.to_i << 3) +
      (rst.to_i << 2) + (syn.to_i << 1) + fin.to_i
    end

    # Helper to determine if this flag is a 1 or a 0.
    def zero_or_one(i=0)
      if i == 0 || i == false || i == nil
        0
      else
        1
      end
    end

    # Setter for the Urgent flag.
    def urg=(i); self[:urg] = zero_or_one(i); end
    # Setter for the Acknowlege flag.
    def ack=(i); self[:ack] = zero_or_one(i); end
    # Setter for the Push flag.
    def psh=(i); self[:psh] = zero_or_one(i); end
    # Setter for the Reset flag.
    def rst=(i); self[:rst] = zero_or_one(i); end
    # Setter for the Synchronize flag.
    def syn=(i); self[:syn] = zero_or_one(i); end
    # Setter for the Finish flag.
    def fin=(i); self[:fin] = zero_or_one(i); end

    # Reads a string to populate the object.
    def read(str)
      force_binary(str)
      return self if str.nil?
      if 1.respond_to? :ord
        byte = str[0].ord
      else
        byte = str[0]
      end
      self[:urg] = byte & 0b00100000 == 0b00100000 ? 1 : 0
      self[:ack] = byte & 0b00010000 == 0b00010000 ? 1 : 0
      self[:psh] = byte & 0b00001000 == 0b00001000 ? 1 : 0
      self[:rst] = byte & 0b00000100 == 0b00000100 ? 1 : 0
      self[:syn] = byte & 0b00000010 == 0b00000010 ? 1 : 0
      self[:fin] = byte & 0b00000001 == 0b00000001 ? 1 : 0
      self
    end

  end
end
