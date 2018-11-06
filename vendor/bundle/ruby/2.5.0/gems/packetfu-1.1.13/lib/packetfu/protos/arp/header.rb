# -*- coding: binary -*-
module PacketFu
  # ARPHeader is a complete ARP struct, used in ARPPacket. 
  #
  # ARP is used to discover the machine address of nearby devices.
  #
  # See http://www.networksorcery.com/enp/protocol/arp.htm for details.
  #
  # ==== Header Definition
  #
  #	 Int16   :arp_hw          Default: 1       # Ethernet
  #	 Int16   :arp_proto,      Default: 0x8000  # IP
  #	 Int8    :arp_hw_len,     Default: 6
  #	 Int8    :arp_proto_len,  Default: 4
  #	 Int16   :arp_opcode,     Default: 1       # 1: Request, 2: Reply, 3: Request-Reverse, 4: Reply-Reverse
  #	 EthMac  :arp_src_mac                      # From eth.rb
  #	 Octets  :arp_src_ip                       # From ip.rb
  #	 EthMac  :arp_dst_mac                      # From eth.rb
  #	 Octets  :arp_dst_ip                       # From ip.rb
  #	 String  :body
  class ARPHeader < Struct.new(:arp_hw, :arp_proto, :arp_hw_len,
                               :arp_proto_len, :arp_opcode,
                               :arp_src_mac, :arp_src_ip,
                               :arp_dst_mac, :arp_dst_ip,
                               :body)
    include StructFu

    def initialize(args={})
      src_mac = args[:arp_src_mac] || (args[:config][:eth_src] if args[:config])
      src_ip_bin = args[:arp_src_ip]   || (args[:config][:ip_src_bin] if args[:config])

      super( 
        Int16.new(args[:arp_hw] || 1), 
        Int16.new(args[:arp_proto] ||0x0800),
        Int8.new(args[:arp_hw_len] || 6), 
        Int8.new(args[:arp_proto_len] || 4), 
        Int16.new(args[:arp_opcode] || 1),
        EthMac.new.read(src_mac),
        Octets.new.read(src_ip_bin),
        EthMac.new.read(args[:arp_dst_mac]),
        Octets.new.read(args[:arp_dst_ip]),
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
      self[:arp_hw].read(str[0,2])
      self[:arp_proto].read(str[2,2])
      self[:arp_hw_len].read(str[4,1])
      self[:arp_proto_len].read(str[5,1])
      self[:arp_opcode].read(str[6,2])
      self[:arp_src_mac].read(str[8,6])
      self[:arp_src_ip].read(str[14,4])
      self[:arp_dst_mac].read(str[18,6])
      self[:arp_dst_ip].read(str[24,4])
      self[:body].read(str[28,str.size])
      self
    end

    # Setter for the ARP hardware type.
    def arp_hw=(i); typecast i; end
    # Getter for the ARP hardware type.
    def arp_hw; self[:arp_hw].to_i; end
    # Setter for the ARP protocol.
    def arp_proto=(i); typecast i; end
    # Getter for the ARP protocol.
    def arp_proto; self[:arp_proto].to_i; end
    # Setter for the ARP hardware type length.
    def arp_hw_len=(i); typecast i; end
    # Getter for the ARP hardware type length.
    def arp_hw_len; self[:arp_hw_len].to_i; end
    # Setter for the ARP protocol length.
    def arp_proto_len=(i); typecast i; end
    # Getter for the ARP protocol length.
    def arp_proto_len; self[:arp_proto_len].to_i; end
    # Setter for the ARP opcode. 
    def arp_opcode=(i); typecast i; end
    # Getter for the ARP opcode. 
    def arp_opcode; self[:arp_opcode].to_i; end
    # Setter for the ARP source MAC address.
    def arp_src_mac=(i); typecast i; end
    # Getter for the ARP source MAC address.
    def arp_src_mac; self[:arp_src_mac].to_s; end
    # Getter for the ARP source IP address.
    def arp_src_ip=(i); typecast i; end
    # Setter for the ARP source IP address.
    def arp_src_ip; self[:arp_src_ip].to_s; end
    # Setter for the ARP destination MAC address.
    def arp_dst_mac=(i); typecast i; end
    # Setter for the ARP destination MAC address.
    def arp_dst_mac; self[:arp_dst_mac].to_s; end
    # Setter for the ARP destination IP address.
    def arp_dst_ip=(i); typecast i; end
    # Getter for the ARP destination IP address.
    def arp_dst_ip; self[:arp_dst_ip].to_s; end

    # Set the source MAC address in a more readable way.
    def arp_saddr_mac=(mac)
      mac = EthHeader.mac2str(mac)
      self[:arp_src_mac].read(mac)
      self.arp_src_mac
    end

    # Get a more readable source MAC address.
    def arp_saddr_mac
      EthHeader.str2mac(self[:arp_src_mac].to_s)
    end

    # Set the destination MAC address in a more readable way.
    def arp_daddr_mac=(mac)
      mac = EthHeader.mac2str(mac)
      self[:arp_dst_mac].read(mac)
      self.arp_dst_mac
    end

    # Get a more readable source MAC address.
    def arp_daddr_mac
      EthHeader.str2mac(self[:arp_dst_mac].to_s)
    end

    # Set a more readable source IP address. 
    def arp_saddr_ip=(addr)
      self[:arp_src_ip].read_quad(addr)
    end

    # Get a more readable source IP address. 
    def arp_saddr_ip
      self[:arp_src_ip].to_x
    end

    # Set a more readable destination IP address.
    def arp_daddr_ip=(addr)
      self[:arp_dst_ip].read_quad(addr)
    end
    
    # Get a more readable destination IP address.
    def arp_daddr_ip
      self[:arp_dst_ip].to_x
    end

    # Readability aliases

    alias :arp_src_mac_readable :arp_saddr_mac
    alias :arp_dst_mac_readable :arp_daddr_mac
    alias :arp_src_ip_readable :arp_saddr_ip
    alias :arp_dst_ip_readable :arp_daddr_ip

    def arp_proto_readable
      "0x%04x" % arp_proto
    end

  end # class ARPHeader
end
