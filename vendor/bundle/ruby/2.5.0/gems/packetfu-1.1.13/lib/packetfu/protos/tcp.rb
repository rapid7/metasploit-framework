# -*- coding: binary -*-
require 'packetfu/protos/eth/header'
require 'packetfu/protos/eth/mixin'

require 'packetfu/protos/tcp/header'
require 'packetfu/protos/tcp/mixin'

require 'packetfu/protos/ip/header'
require 'packetfu/protos/ip/mixin'

module PacketFu
  # TCPPacket is used to construct TCP packets. They contain an EthHeader, an IPHeader, and a TCPHeader.
  #
  # == Example
  #
  #    tcp_pkt = PacketFu::TCPPacket.new
  #    tcp_pkt.tcp_flags.syn=1
  #    tcp_pkt.tcp_dst=80
  #    tcp_pkt.tcp_win=5840
  #    tcp_pkt.tcp_options="mss:1460,sack.ok,ts:#{rand(0xffffffff)};0,nop,ws:7"
  #
  #    tcp_pkt.ip_saddr=[rand(0xff),rand(0xff),rand(0xff),rand(0xff)].join('.')
  #    tcp_pkt.ip_daddr=[rand(0xff),rand(0xff),rand(0xff),rand(0xff)].join('.')
  #
  #    tcp_pkt.recalc
  #    tcp_pkt.to_f('/tmp/tcp.pcap')
  #
  # == Parameters
  #  :eth
  #    A pre-generated EthHeader object.
  #  :ip
  #    A pre-generated IPHeader object.
  #  :flavor
  #    TODO: Sets the "flavor" of the TCP packet. This will include TCP options and the initial window
  #    size, per stack. There is a lot of variety here, and it's one of the most useful methods to
  #    remotely fingerprint devices. :flavor will span both ip and tcp for consistency.
  #   :type
  #    TODO: Set up particular types of packets (syn, psh_ack, rst, etc). This can change the initial flavor.
  #  :config
  #   A hash of return address details, often the output of Utils.whoami?
  class TCPPacket < Packet
    include ::PacketFu::EthHeaderMixin
    include ::PacketFu::IPHeaderMixin
    include ::PacketFu::TCPHeaderMixin

    attr_accessor :eth_header, :ip_header, :tcp_header

    def self.can_parse?(str)
      return false unless str.size >= 54
      return false unless EthPacket.can_parse? str
      return false unless IPPacket.can_parse? str
      return false unless str[23,1] == "\x06"
      return true
    end

    def read(str=nil, args={})
      raise "Cannot parse `#{str}'" unless self.class.can_parse?(str)
      @eth_header.read(str)

      # Strip off any extra data, if we are asked to do so.
      if args[:strip]
        tcp_body_len = self.ip_len - self.ip_hlen - (self.tcp_hlen * 4)
        @tcp_header.body.read(@tcp_header.body.to_s[0,tcp_body_len])
      end
      super(args)
      self
    end

    def initialize(args={})
      @eth_header = 	(args[:eth] || EthHeader.new)
      @ip_header 	= 	(args[:ip]	|| IPHeader.new)
      @tcp_header = 	(args[:tcp] || TCPHeader.new)
      @tcp_header.flavor = args[:flavor].to_s.downcase

      @ip_header.body = @tcp_header
      @eth_header.body = @ip_header
      @headers = [@eth_header, @ip_header, @tcp_header]

      @ip_header.ip_proto=0x06
      super
      if args[:flavor]
        tcp_calc_flavor(@tcp_header.flavor)
      else
        tcp_calc_sum
      end
    end

    # Sets the correct flavor for TCP Packets. Recognized flavors are:
    #   windows, linux, freebsd
    def tcp_calc_flavor(str)
      ts_val = Time.now.to_i + rand(0x4fffffff)
      ts_sec = rand(0xffffff)
      case @tcp_header.flavor = str.to_s.downcase
      when "windows" # WinXP's default syn
        @tcp_header.tcp_win = 0x4000
        @tcp_header.tcp_options="MSS:1460,NOP,NOP,SACKOK"
        @tcp_header.tcp_src = rand(5000 - 1026) + 1026
        @ip_header.ip_ttl = 64
      when "linux" # Ubuntu Linux 2.6.24-19-generic default syn
        @tcp_header.tcp_win = 5840
        @tcp_header.tcp_options="MSS:1460,SACKOK,TS:#{ts_val};0,NOP,WS:7"
        @tcp_header.tcp_src = rand(61_000 - 32_000) + 32_000
        @ip_header.ip_ttl = 64
      when "freebsd" # Freebsd
        @tcp_header.tcp_win = 0xffff
        @tcp_header.tcp_options="MSS:1460,NOP,WS:3,NOP,NOP,TS:#{ts_val};#{ts_sec},SACKOK,EOL,EOL"
        @ip_header.ip_ttl = 64
      else
        @tcp_header.tcp_options="MSS:1460,NOP,NOP,SACKOK"
      end
      tcp_calc_sum
    end

    # tcp_calc_sum() computes the TCP checksum, and is called upon intialization. It usually
    # should be called just prior to dropping packets to a file or on the wire.
    #--
    # This is /not/ delegated down to @tcp_header since we need info
    # from the IP header, too.
    #++
    def tcp_calc_sum
      checksum =  (ip_src.to_i >> 16)
      checksum += (ip_src.to_i & 0xffff)
      checksum += (ip_dst.to_i >> 16)
      checksum += (ip_dst.to_i & 0xffff)
      checksum += 0x06 # TCP Protocol.
      checksum +=	(ip_len.to_i - ((ip_hl.to_i) * 4))
      checksum += tcp_src
      checksum += tcp_dst
      checksum += (tcp_seq.to_i >> 16)
      checksum += (tcp_seq.to_i & 0xffff)
      checksum += (tcp_ack.to_i >> 16)
      checksum += (tcp_ack.to_i & 0xffff)
      checksum += ((tcp_hlen << 12) + 
                   (tcp_reserved << 9) + 
                   (tcp_ecn.to_i << 6) + 
                   tcp_flags.to_i
                  )
      checksum += tcp_win
      checksum += tcp_urg

      chk_tcp_opts = (tcp_opts.to_s.size % 2 == 0 ? tcp_opts.to_s : tcp_opts.to_s + "\x00") 
      chk_tcp_opts.unpack("n*").each {|x| checksum = checksum + x }
      if (ip_len - ((ip_hl + tcp_hlen) * 4)) >= 0
        real_tcp_payload = payload[0,( ip_len - ((ip_hl + tcp_hlen) * 4) )] # Can't forget those pesky FCSes!
      else
        real_tcp_payload = payload # Something's amiss here so don't bother figuring out where the real payload is.
      end
      chk_payload = (real_tcp_payload.size % 2 == 0 ? real_tcp_payload : real_tcp_payload + "\x00") # Null pad if it's odd.
      chk_payload.unpack("n*").each {|x| checksum = checksum+x }
      checksum = checksum % 0xffff
      checksum = 0xffff - checksum
      checksum == 0 ? 0xffff : checksum
      @tcp_header.tcp_sum = checksum
    end

    # Recalculates various fields of the TCP packet.
    #
    # ==== Parameters
    #
    #   :all
    #     Recomputes all calculated fields.
    #   :tcp_sum
    #     Recomputes the TCP checksum.
    #   :tcp_hlen
    #     Recomputes the TCP header length. Useful after options are added.
    def tcp_recalc(arg=:all)
      case arg
      when :tcp_sum
        tcp_calc_sum
      when :tcp_hlen
        @tcp_header.tcp_recalc :tcp_hlen
      when :all
        @tcp_header.tcp_recalc :all
        tcp_calc_sum
      else
        raise ArgumentError, "No such field `#{arg}'"
      end
    end

    # TCP packets are denoted by a "T  ", followed by size,
    # source and dest information, packet flags, sequence
    # number, and IPID.
    def peek_format
      peek_data = ["T  "]
      peek_data << "%-5d" % self.to_s.size
      peek_data << "%-21s" % "#{self.ip_saddr}:#{self.tcp_src}"
      peek_data << "->"
      peek_data << "%21s" % "#{self.ip_daddr}:#{self.tcp_dst}"
      flags = ' ['
      flags << self.tcp_flags_dotmap
      flags << '] '
      peek_data << flags
      peek_data << "S:"
      peek_data << "%08x" % self.tcp_seq
      peek_data << "|I:"
      peek_data << "%04x" % self.ip_id
      peek_data.join
    end

  end

end
