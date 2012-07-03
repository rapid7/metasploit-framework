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

	# ARPPacket is used to construct ARP packets. They contain an EthHeader and an ARPHeader.
	# == Example
	#
  #  require 'packetfu'
	#  arp_pkt = PacketFu::ARPPacket.new(:flavor => "Windows")
	#  arp_pkt.arp_saddr_mac="00:1c:23:44:55:66"  # Your hardware address
	#  arp_pkt.arp_saddr_ip="10.10.10.17"  # Your IP address
	#  arp_pkt.arp_daddr_ip="10.10.10.1"  # Target IP address
	#  arp_pkt.arp_opcode=1  # Request
	# 
	#  arp_pkt.to_w('eth0')	# Inject on the wire. (requires root)
  #  arp_pkt.to_f('/tmp/arp.pcap') # Write to a file.
	#
	# == Parameters
	#
	#  :flavor
	#   Sets the "flavor" of the ARP packet. Choices are currently:
	#     :windows, :linux, :hp_deskjet 
	#  :eth
	#   A pre-generated EthHeader object. If not specified, a new one will be created.
	#  :arp
	#   A pre-generated ARPHeader object. If not specificed, a new one will be created.
	#  :config
	#   A hash of return address details, often the output of Utils.whoami?
	class ARPPacket < Packet

		attr_accessor :eth_header, :arp_header

		def self.can_parse?(str)
			return false unless EthPacket.can_parse? str
			return false unless str.size >= 28
			return false unless str[12,2] == "\x08\x06"
			true
		end

		def read(str=nil,args={})
			raise "Cannot parse `#{str}'" unless self.class.can_parse?(str)
			@eth_header.read(str)
			@arp_header.read(str[14,str.size])
			@eth_header.body = @arp_header
			super(args)
			self
		end

		def initialize(args={})
			@eth_header = EthHeader.new(args).read(args[:eth])
			@arp_header = ARPHeader.new(args).read(args[:arp]) 
			@eth_header.eth_proto = "\x08\x06"
			@eth_header.body=@arp_header

			# Please send more flavors to todb+packetfu@planb-security.net.
			# Most of these initial fingerprints come from one (1) sample.
			case (args[:flavor].nil?) ? :nil : args[:flavor].to_s.downcase.intern
			when :windows; @arp_header.body = "\x00" * 64				# 64 bytes of padding 
			when :linux; @arp_header.body = "\x00" * 4 +				# 32 bytes of padding 
				"\x00\x07\x5c\x14" + "\x00" * 4 +
				"\x00\x0f\x83\x34" + "\x00\x0f\x83\x74" +
				"\x01\x11\x83\x78" + "\x00\x00\x00\x0c" + 
				"\x00\x00\x00\x00"
			when :hp_deskjet; 																	# Pads up to 60 bytes.
				@arp_header.body = "\xe0\x90\x0d\x6c" + 
				"\xff\xff\xee\xee" + "\x00" * 4 + 
				"\xe0\x8f\xfa\x18\x00\x20"	
			else; @arp_header.body = "\x00" * 18								# Pads up to 60 bytes.
			end

			@headers = [@eth_header, @arp_header]
			super
		end

		# Generates summary data for ARP packets.
		def peek_format
			peek_data = ["A  "]
			peek_data << "%-5d" % self.to_s.size
			peek_data << arp_saddr_mac
			peek_data << "(#{arp_saddr_ip})"
			peek_data << "->"
			peek_data << case arp_daddr_mac
										when "00:00:00:00:00:00"; "Bcast00"
										when "ff:ff:ff:ff:ff:ff"; "BcastFF"
										else; arp_daddr_mac
										end
			peek_data << "(#{arp_daddr_ip})"
			peek_data << ":"
			peek_data << case arp_opcode
										when 1; "Requ"
										when 2; "Repl"
										when 3; "RReq"
										when 4; "RRpl"
										when 5; "IReq"
										when 6; "IRpl"
										else; "0x%02x" % arp_opcode
										end
			peek_data.join
		end

		# While there are lengths in ARPPackets, there's not
		# much to do with them.
		def recalc(args={})
			@headers[0].inspect
		end

	end

end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
