# -*- coding: binary -*-
require 'packetfu/protos/tcp/reserved'
require 'packetfu/protos/tcp/hlen'
require 'packetfu/protos/tcp/ecn'
require 'packetfu/protos/tcp/flags'
require 'packetfu/protos/tcp/option'
require 'packetfu/protos/tcp/options'


module PacketFu
  # TCPHeader is a complete TCP struct, used in TCPPacket. Most IP traffic is TCP-based, by
  # volume.
  #
  # For more on TCP packets, see http://www.networksorcery.com/enp/protocol/tcp.htm
  #
  # ==== Header Definition
  # 
  #   Int16        :tcp_src       Default: random 
  #   Int16        :tcp_dst
  #   Int32        :tcp_seq       Default: random
  #   Int32        :tcp_ack
  #   TcpHlen      :tcp_hlen      Default: 5           # Must recalc as options are set. 
  #   TcpReserved  :tcp_reserved  Default: 0
  #   TcpEcn       :tcp_ecn
  #   TcpFlags     :tcp_flags
  #   Int16        :tcp_win,      Default: 0           # WinXP's default syn packet
  #   Int16        :tcp_sum,      Default: calculated  # Must set this upon generation.
  #   Int16        :tcp_urg
  #   TcpOptions   :tcp_opts
  #   String       :body
  #
  # See also TcpHlen, TcpReserved, TcpEcn, TcpFlags, TcpOpts
  class TCPHeader < Struct.new(:tcp_src, :tcp_dst,
                               :tcp_seq,
                               :tcp_ack,
                               :tcp_hlen, :tcp_reserved, :tcp_ecn, :tcp_flags, :tcp_win, 
                               :tcp_sum, :tcp_urg, 
                               :tcp_opts, :body)
    include StructFu

    def initialize(args={})
      @random_seq = rand(0xffffffff)
      @random_src = rand_port
      super(
        Int16.new(args[:tcp_src] || tcp_calc_src),
        Int16.new(args[:tcp_dst]),
        Int32.new(args[:tcp_seq] || tcp_calc_seq),
        Int32.new(args[:tcp_ack]),
        TcpHlen.new(:hlen => (args[:tcp_hlen] || 5)),
        TcpReserved.new(args[:tcp_reserved] || 0),
        TcpEcn.new(args[:tcp_ecn]),
        TcpFlags.new(args[:tcp_flags]),
        Int16.new(args[:tcp_win] || 0x4000),
        Int16.new(args[:tcp_sum] || 0),
        Int16.new(args[:tcp_urg]),
        TcpOptions.new.read(args[:tcp_opts]),
        StructFu::String.new.read(args[:body])
      )
    end

    attr_accessor :flavor

    # Helper function to create the string for Hlen, Reserved, ECN, and Flags.
    def bits_to_s
      bytes = []
      bytes[0] = (self[:tcp_hlen].to_i << 4) +
        (self[:tcp_reserved].to_i << 1) +
        self[:tcp_ecn].n.to_i
      bytes[1] = (self[:tcp_ecn].c.to_i << 7) +
        (self[:tcp_ecn].e.to_i << 6) +
        self[:tcp_flags].to_i
      bytes.pack("CC")
    end

    # Returns the object in string form.
    def to_s
      hdr = self.to_a.map do |x|
        if x.kind_of? TcpHlen
          bits_to_s
        elsif x.kind_of? TcpReserved
          next
        elsif x.kind_of? TcpEcn
          next
        elsif x.kind_of? TcpFlags
          next
        else
          x.to_s
        end
      end
      hdr.flatten.join
    end

    # Reads a string to populate the object.
    def read(str)
      force_binary(str)
      return self if str.nil?
      self[:tcp_src].read(str[0,2])
      self[:tcp_dst].read(str[2,2])
      self[:tcp_seq].read(str[4,4])
      self[:tcp_ack].read(str[8,4])
      self[:tcp_hlen].read(str[12,1])
      self[:tcp_reserved].read(str[12,1])
      self[:tcp_ecn].read(str[12,2])
      self[:tcp_flags].read(str[13,1])
      self[:tcp_win].read(str[14,2])
      self[:tcp_sum].read(str[16,2])
      self[:tcp_urg].read(str[18,2])
      self[:tcp_opts].read(str[20,((self[:tcp_hlen].to_i * 4) - 20)])
      self[:body].read(str[(self[:tcp_hlen].to_i * 4),str.size])
      self
    end

    # Setter for the TCP source port.
    def tcp_src=(i); typecast i; end
    # Getter for the TCP source port.
    def tcp_src; self[:tcp_src].to_i; end
    # Setter for the TCP destination port.
    def tcp_dst=(i); typecast i; end
    # Getter for the TCP destination port.
    def tcp_dst; self[:tcp_dst].to_i; end
    # Setter for the TCP sequence number.
    def tcp_seq=(i); typecast i; end
    # Getter for the TCP sequence number.
    def tcp_seq; self[:tcp_seq].to_i; end
    # Setter for the TCP ackowlegement number.
    def tcp_ack=(i); typecast i; end
    # Getter for the TCP ackowlegement number.
    def tcp_ack; self[:tcp_ack].to_i; end
    # Setter for the TCP window size number.
    def tcp_win=(i); typecast i; end
    # Getter for the TCP window size number.
    def tcp_win; self[:tcp_win].to_i; end
    # Setter for the TCP checksum.
    def tcp_sum=(i); typecast i; end
    # Getter for the TCP checksum.
    def tcp_sum; self[:tcp_sum].to_i; end
    # Setter for the TCP urgent field.
    def tcp_urg=(i); typecast i; end
    # Getter for the TCP urgent field.
    def tcp_urg; self[:tcp_urg].to_i; end

    # Getter for the TCP Header Length value.
    def tcp_hlen; self[:tcp_hlen].to_i; end
    # Setter for the TCP Header Length value. Can take
    # either a string or an integer. Note that if it's
    # a string, the top four bits are used.
    def tcp_hlen=(i)
      case i
      when PacketFu::TcpHlen
        self[:tcp_hlen] = i
      when Numeric
        self[:tcp_hlen] = TcpHlen.new(:hlen => i.to_i)
      else
        self[:tcp_hlen].read(i)
      end
    end

    # Getter for the TCP Reserved field.
    def tcp_reserved; self[:tcp_reserved].to_i; end
    # Setter for the TCP Reserved field.
    def tcp_reserved=(i)
      case i
      when PacketFu::TcpReserved
        self[:tcp_reserved]=i
      when Numeric
        args = {}
        args[:r1] = (i & 0b100) >> 2
        args[:r2] = (i & 0b010) >> 1
        args[:r3] = (i & 0b001)
        self[:tcp_reserved] = TcpReserved.new(args)
      else
        self[:tcp_reserved].read(i)
      end
    end

    # Getter for the ECN bits. 
    def tcp_ecn; self[:tcp_ecn].to_i; end
    # Setter for the ECN bits. 
    def tcp_ecn=(i)
      case i
      when PacketFu::TcpEcn
        self[:tcp_ecn]=i
      when Numeric
        args = {}
        args[:n] = (i & 0b100) >> 2
        args[:c] = (i & 0b010) >> 1
        args[:e] = (i & 0b001)
        self[:tcp_ecn] = TcpEcn.new(args)
      else
        self[:tcp_ecn].read(i)
      end
    end

    # Getter for TCP Options.
    def tcp_opts; self[:tcp_opts].to_s; end
    # Setter for TCP Options.
    def tcp_opts=(i)
      case i
      when PacketFu::TcpOptions
        self[:tcp_opts]=i
      else
        self[:tcp_opts].read(i)
      end
    end

    # Resets the sequence number to a new random number.
    def tcp_calc_seq; @random_seq; end
    # Resets the source port to a new random number.
    def tcp_calc_src; @random_src; end

    # Returns the actual length of the TCP options.
    def tcp_opts_len
      self[:tcp_opts].to_s.size
    end

    # Sets and returns the true length of the TCP Header.
    # TODO: Think about making all the option stuff safer. 
    def tcp_calc_hlen
      self[:tcp_hlen] = TcpHlen.new(:hlen => ((20 + tcp_opts_len) / 4))
    end

    # Generates a random high port. This is affected by packet flavor.
    def rand_port
      rand(0xffff - 1025) + 1025
    end

    # Gets a more readable option list.
    def tcp_options
     self[:tcp_opts].decode
    end

    # Gets a more readable flags list
    def tcp_flags_dotmap
      dotmap = tcp_flags.members.map do |flag|
        status = self.tcp_flags.send flag
        status == 0 ? "." : flag.to_s.upcase[0].chr
      end
      dotmap.join
    end

    # Sets a more readable option list.
    def tcp_options=(arg)
      self[:tcp_opts].encode arg
    end

    # Equivalent to tcp_src.
    def tcp_sport
      self.tcp_src.to_i
    end

    # Equivalent to tcp_src=.
    def tcp_sport=(arg)
      self.tcp_src=(arg)
    end

    # Equivalent to tcp_dst.
    def tcp_dport
      self.tcp_dst.to_i
    end
    
    # Equivalent to tcp_dst=.
    def tcp_dport=(arg)
      self.tcp_dst=(arg)
    end

    # Recalculates calculated fields for TCP (except checksum which is at the Packet level).
    def tcp_recalc(arg=:all)
      case arg
      when :tcp_hlen
        tcp_calc_hlen
      when :tcp_src
        @random_tcp_src = rand_port
      when :tcp_sport
        @random_tcp_src = rand_port
      when :tcp_seq
        @random_tcp_seq = rand(0xffffffff) 
      when :all
        tcp_calc_hlen
        @random_tcp_src = rand_port
        @random_tcp_seq = rand(0xffffffff) 
      else
        raise ArgumentError, "No such field `#{arg}'"
      end
    end

    # Readability aliases

    alias :tcp_flags_readable :tcp_flags_dotmap

    def tcp_ack_readable
      "0x%08x" % tcp_ack
    end

    def tcp_seq_readable
      "0x%08x" % tcp_seq
    end

    def tcp_sum_readable
      "0x%04x" % tcp_sum
    end

    def tcp_opts_readable
      tcp_options
    end

  end

end
