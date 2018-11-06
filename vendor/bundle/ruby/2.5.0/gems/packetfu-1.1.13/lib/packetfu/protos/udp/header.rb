# -*- coding: binary -*-
module PacketFu

  # UDPHeader is a complete UDP struct, used in UDPPacket. Many Internet-critical protocols
  # rely on UDP, such as DNS and World of Warcraft.
  #
  # For more on UDP packets, see http://www.networksorcery.com/enp/protocol/udp.htm
  #
  # ==== Header Definition
  #  Int16   :udp_src
  #  Int16   :udp_dst
  #  Int16   :udp_len  Default: calculated
  #  Int16   :udp_sum  Default: 0. Often calculated. 
  #  String  :body
  class UDPHeader < Struct.new(:udp_src, :udp_dst, :udp_len, :udp_sum, :body)

    include StructFu

    def initialize(args={})
      super(
        Int16.new(args[:udp_src]),
        Int16.new(args[:udp_dst]),
        Int16.new(args[:udp_len] || udp_calc_len),
        Int16.new(args[:udp_sum]),
        StructFu::String.new.read(args[:body])
      )
    end

    # Returns the object in string form.
    def to_s
      self.to_a.map {|x| x.to_s}.join
    end

    # Reads a string to populate the object.
    def read(str)
      force_binary(str)
      return self if str.nil?
      self[:udp_src].read(str[0,2])
      self[:udp_dst].read(str[2,2])
      self[:udp_len].read(str[4,2])
      self[:udp_sum].read(str[6,2])
      self[:body].read(str[8,str.size])
      self
    end

    # Setter for the UDP source port.
    def udp_src=(i); typecast i; end
    # Getter for the UDP source port.
    def udp_src; self[:udp_src].to_i; end
    # Setter for the UDP destination port.
    def udp_dst=(i); typecast i; end
    # Getter for the UDP destination port.
    def udp_dst; self[:udp_dst].to_i; end
    # Setter for the length field. Usually should be recalc()'ed instead.
    def udp_len=(i); typecast i; end
    # Getter for the length field.
    def udp_len; self[:udp_len].to_i; end
    # Setter for the checksum. Usually should be recalc()'ed instad.
    def udp_sum=(i); typecast i; end
    # Getter for the checksum.
    def udp_sum; self[:udp_sum].to_i; end

    # Returns the true length of the UDP packet.
    def udp_calc_len
      body.to_s.size + 8
    end

    # Recalculates calculated fields for UDP.
    def udp_recalc(args=:all)
      arg = arg.intern if arg.respond_to? :intern
      case args
      when :udp_len
        self.udp_len = udp_calc_len
      when :all
        self.udp_recalc(:udp_len)
      else
        raise ArgumentError, "No such field `#{arg}'"
      end
    end

    # Equivalent to udp_src.to_i
    def udp_sport
      self.udp_src
    end

    # Equivalent to udp_src=
    def udp_sport=(arg)
      self.udp_src=(arg)
    end

    # Equivalent to udp_dst
    def udp_dport
      self.udp_dst
    end
    
    # Equivalent to udp_dst=
    def udp_dport=(arg)
      self.udp_dst=(arg)
    end

    # Readability aliases

    def udp_sum_readable
      "0x%04x" % udp_sum
    end

  end
end
