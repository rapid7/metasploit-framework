
module Pcap
  class Packet
    def to_s
      'Some packet'
    end

    def inspect
      "#<#{type}: #{self}>"
    end
  end

  class IPPacket
    def to_s
      "#{ip_src} > #{ip_dst}"
    end
  end

  class TCPPacket
    def tcp_data_len
      ip_len - 4 * (ip_hlen + tcp_hlen)
    end

    def tcp_flags_s
      return \
	(tcp_urg? ? 'U' : '.') +
	(tcp_ack? ? 'A' : '.') +
	(tcp_psh? ? 'P' : '.') +
	(tcp_rst? ? 'R' : '.') +
	(tcp_syn? ? 'S' : '.') +
        (tcp_fin? ? 'F' : '.')
    end

    def to_s
      "#{src}:#{sport} > #{dst}:#{dport} #{tcp_flags_s}"
    end
  end

  class UDPPacket
    def to_s
      "#{src}:#{sport} > #{dst}:#{dport} len #{udp_len} sum #{udp_sum}"
    end
  end

  class ICMPPacket
    def to_s
      "#{src} > #{dst}: icmp: #{icmp_typestr}"
    end
  end

  #
  # Backword compatibility
  #
  IpPacket = IPPacket
  IpAddress = IPAddress
  TcpPacket = TCPPacket
  UdpPacket = UDPPacket

  # IpAddress is now obsolete.
  # New class IPAddress is implemented in C.
=begin
  class IpAddress
    def initialize(a)
      raise AurgumentError unless a.is_a?(Integer)
      @addr = a
    end

    def to_i
      return @addr
    end

    def ==(other)
      @addr == other.to_i
    end

    alias === ==
    alias eql? ==

    def to_num_s
        return ((@addr >> 24) & 0xff).to_s + "." +
          ((@addr >> 16) & 0xff).to_s + "." +
          ((@addr >> 8) & 0xff).to_s + "." +
          (@addr & 0xff).to_s;
    end

    def hostname
      addr = self.to_num_s
      # "require 'socket'" is here because of the order of
      #   ext initialization in static linked binary
      require 'socket'
      begin
	return Socket.gethostbyname(addr)[0]
      rescue SocketError
	return addr
      end
    end

    def to_s
      if Pcap.convert?
        return hostname
      else
        return to_num_s
      end
    end
  end
=end
end

class Time
  # tcpdump style format
  def tcpdump
    sprintf "%0.2d:%0.2d:%0.2d.%0.6d", hour, min, sec, tv_usec
  end
end

autoload :Pcaplet, 'pcaplet'
