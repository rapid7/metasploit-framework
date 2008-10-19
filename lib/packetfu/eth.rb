
module PacketFu

	# EthOui is the Organizationally Unique Identifier portion of a MAC address, used in EthHeader.
	#
	# See the OUI list at http://standards.ieee.org/regauth/oui/oui.txt
	#
	# ==== Header Definition
	#
	#  bit1     :b0
	#  bit1     :b1
	#  bit1     :b2
	#  bit1     :b3
	#  bit1     :b4
	#  bit1     :b5
	#  bit1     :local
	#  bit1     :multicast
	#  uint16be :oui,      :initial_value => 0x1ac5 # :)
	class EthOui < BinData::MultiValue
		bit1			:b0
		bit1			:b1
		bit1			:b2
		bit1			:b3
		bit1			:b4
		bit1			:b5
		bit1			:local
		bit1			:multicast
		uint16be	:oui,	:initial_value => 0x1ac5 # :)
	end

  # EthNic is the Network Interface Controler portion of a MAC address, used in EthHeader.
	#
	# ==== Header Definition
	#
	#   unit8 :n1
	#   unit8 :n2
	#   unit8 :n3
	#
	class EthNic < BinData::MultiValue
		uint8		:n1
		uint8		:n2
		uint8		:n3
	end

	# EthMac is the combination of an EthOui and EthNic, used in EthHeader.
	#
	# ==== Header Definition
	#
	#   eth_oui :oui  # See EthOui
	#   eth_nic :nic  # See EthOui
	class EthMac < BinData::MultiValue
		eth_oui	:oui		# See EthOui
		eth_nic	:nic		# See EthOui
	end
	
	# EthHeader is a complete Ethernet struct, used in EthPacket. 
	# It's the base header for all other protocols, such as IPHeader, TCPHeader, etc. 
	#
	# For more on the construction on MAC addresses, see http://en.wikipedia.org/wiki/MAC_address
	#
	# ==== Header Definition
	#
	#  eth_mac  :eth_dst                             # See EthMac
	#  eth_mac  :eth_src                             # See EthMac
	#  uint16be :eth_proto, :initial_value => 0x0800 # IP 0x0800, Arp 0x0806
	#  rest     :body
	class EthHeader < BinData::MultiValue
		eth_mac		:eth_dst														 # See EthMac
		eth_mac		:eth_src														 # See EthMac
		uint16be	:eth_proto, :initial_value => 0x0800 # IP 0x0800, Arp 0x0806
		rest			:body

		# Set the source MAC address in a more readable way.
		def eth_saddr=(mac)
			mac = EthHeader.mac2str(mac)
			self.eth_src.read(mac)
			self.eth_src
		end

		# Returns a more readable source MAC address.
		def eth_saddr
			EthHeader.str2mac(self.eth_src.to_s)
		end

		# Set the destination MAC address in a more readable way.
		def eth_daddr=(mac)
			mac = EthHeader.mac2str(mac)
			self.eth_dst.read(mac)
			self.eth_dst
		end

		# Returns a more readable source MAC address.
		def eth_daddr
			EthHeader.str2mac(self.eth_dst.to_s)
		end

		# Converts a readable MAC (11:22:33:44:55:66) to a binary string. Readable MAC's may be split on colons, dots, 
		# spaces, or underscores.
		#
		# irb> PacketFu::EthHeader.mac2str("11:22:33:44:55:66")
		#
		# #=> "\021\"3DUf"
		def self.mac2str(mac)
			if mac.split(/[:\x2d\x2e\x5f]/).size == 6
				ret =	mac.split(/[:\x2d\x2e\x20\x5f]/).collect {|x| x.to_i(16)}.pack("C6")
			else
				raise ArgumentError, "Unkown format for mac address."
			end
			return ret
		end

		# Converts a binary string to a readable MAC (11:22:33:44:55:66). 
		#
		# irb> PacketFu::EthHeader.str2mac("\x11\x22\x33\x44\x55\x66")
		#
		# #=> "11:22:33:44:55:66"
		def self.str2mac(mac)
			if mac.size == 6 && mac.class == String
				ret = mac.unpack("C6").collect {|x| sprintf("%02x",x)}.join(":")
			end
		end

	end

	# EthPacket is used to construct Ethernet packets. They contain an EthHeader, and usually
	# other packet types.
	#
	# == Example
	#
  #  require 'packetfu'
	#  eth_pkt = PacketFu::EthPacket.new(:flavor => :apple)
  #  eth_pkt.eth_saddr="01:02:03:04:05:06"
  #  eth_pkt.eth_daddr="0a:0b:0c:0d:0e:0f"
  #  eth_pkt.payload="I'm a lonely little eth packet with no real protocol information to speak of."
  #  puts eth_pkt.to_f('/tmp/eth.pcap').inspect
	#
	# == Parameters
	#
	#  :eth
	#   A pre-generated EthHeader object. If not specified, a new one will be created.
	#  :flavor
	#   TODO: not implemented. Will generate EthPacket objects based on the OUI list.
	#  :config
	#   A hash of return address details, often the output of Utils.whoami?
	class EthPacket < Packet
		attr_accessor :eth_header

		def ethernet?; true; end
						
		def initialize(args={})
			@eth_header = 	(args[:eth] || EthHeader.new)

			@headers = [@eth_header]
			super

		end

	end

end # module PacketFu