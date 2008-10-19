
module PacketFu

	# ARPHeader is a complete ARP struct, used in ARPPacket. 
	#
	# ARP is used to discover the machine address of nearby devices.
	#
	# See http://www.networksorcery.com/enp/protocol/arp.htm for details.
	#
	# ==== Header Definition
	#
	#	 uint16be :arp_hw,        :initial_value => 1      # Ethernet
	#	 uint16be :arp_proto,     :initial_value => 0x0800 # IP
	#	 uint8    :arp_hw_len,    :initial_value => 6
	#	 uint8    :arp_proto_len, :initial_value => 4
	#	 uint16be :arp_opcode,    :initial_value => 1      # 1: Request, 2: Reply, 3: Request-Reverse, 4: Reply-Reverse
	#	 eth_mac  :arp_src_mac                             # From eth.rb
	#	 octets   :arp_src_ip                              # From ip.rb
	#	 eth_mac  :arp_dst_mac                             # From eth.rb
	#	 octets   :arp_dst_ip                              # From ip.rb
	#	 rest     :body
	#
	class ARPHeader < BinData::MultiValue

		uint16be	:arp_hw, 				:initial_value => 1 # Ethernet
		uint16be	:arp_proto, 		:initial_value => 0x0800 # IP
		uint8			:arp_hw_len,		:initial_value => 6
		uint8			:arp_proto_len,	:initial_value => 4
		uint16be	:arp_opcode,		:initial_value => 1 # 1: Request, 2: Reply, 3: Request-Reverse, 4: Reply-Reverse
		eth_mac		:arp_src_mac		# From eth.rb
		octets		:arp_src_ip			# From ip.rb
		eth_mac		:arp_dst_mac		# From eth.rb
		octets		:arp_dst_ip			# From ip.rb
		rest			:body

		# Set the source MAC address in a more readable way.
		def arp_saddr_mac=(mac)
			mac = EthHeader.mac2str(mac)
			self.arp_src_mac.read(mac)
			self.arp_src_mac
		end

		# Returns a more readable source MAC address.
		def arp_saddr_mac
			EthHeader.str2mac(self.arp_src_mac.to_s)
		end

		# Set the destination MAC address in a more readable way.
		def arp_daddr_mac=(mac)
			mac = EthHeader.mac2str(mac)
			self.arp_dst_mac.read(mac)
			self.arp_dst_mac
		end

		# Returns a more readable source MAC address.
		def arp_daddr_mac
			EthHeader.str2mac(self.arp_dst_mac.to_s)
		end

		# Sets a more readable source IP address. 
		def arp_saddr_ip=(addr)
			addr = IPHeader.octet_array(addr)
			arp_src_ip.o1 = addr[0]
			arp_src_ip.o2 = addr[1]
			arp_src_ip.o3 = addr[2]
			arp_src_ip.o4 = addr[3]
		end

		# Returns a more readable source IP address. 
		def arp_saddr_ip
			[arp_src_ip.o1,arp_src_ip.o2,arp_src_ip.o3,arp_src_ip.o4].join('.')
		end

		# Sets a more readable destination IP address.
		def arp_daddr_ip=(addr)
			addr = IPHeader.octet_array(addr)
			arp_dst_ip.o1 = addr[0]
			arp_dst_ip.o2 = addr[1]
			arp_dst_ip.o3 = addr[2]
			arp_dst_ip.o4 = addr[3]
		end
		
		# Returns a more readable destination IP address.
		def arp_daddr_ip
			[arp_dst_ip.o1,arp_dst_ip.o2,arp_dst_ip.o3,arp_dst_ip.o4].join('.')
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

		def ethernet?; true; end
		def arp?;      true; end
		
		def initialize(args={})
			@eth_header = (args[:eth] || EthHeader.new)
			@arp_header = (args[:arp]	|| ARPHeader.new)
			@eth_header.eth_proto = 0x806
			@eth_header.body=@arp_header

			# Please send more flavors to todb-packetfu@planb-security.net.
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

		# Used to generate summary data for ARP packets.
		def peek(args={})
			peek_data = ["A "]
			peek_data << "%-5d" % self.to_s.size
			peek_data << self.arp_saddr_mac
			peek_data << "(#{self.arp_saddr_ip})"
			peek_data << "->"
			peek_data << case self.arp_daddr_mac
										when "00:00:00:00:00:00"; "Bcast00"
										when "ff:ff:ff:ff:ff:ff"; "BcastFF"
										else; self.arp_daddr_mac
										end
			peek_data << "(#{self.arp_daddr_ip})"
			peek_data << ":"
			peek_data << case self.arp_opcode
										when 1; "Requ"
										when 2; "Repl"
										when 3; "RReq"
										when 4; "RRpl"
										when 5; "IReq"
										when 6; "IRpl"
										else; "0x%02x" % self.opcode
										end
			peek_data.join
		end

	end # class ARPPacket

end # module PacketFu