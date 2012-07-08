# -*- coding: binary -*-
module PacketFu

	# EthOui is the Organizationally Unique Identifier portion of a MAC address, used in EthHeader.
	#
	# See the OUI list at http://standards.ieee.org/regauth/oui/oui.txt
	#
	# ==== Header Definition
	#
	#  Fixnum   :b0
	#  Fixnum   :b1
	#  Fixnum   :b2
	#  Fixnum   :b3
	#  Fixnum   :b4
	#  Fixnum   :b5
	#  Fixnum   :local
	#  Fixnum   :multicast
	#  Int16    :oui,       Default: 0x1ac5 :)
	class EthOui < Struct.new(:b5, :b4, :b3, :b2, :b1, :b0, :local, :multicast, :oui)

		# EthOui is unusual in that the bit values do not enjoy StructFu typing.
		def initialize(args={})
			args[:local] ||= 0 
			args[:oui] ||= 0x1ac # :)
			args.each_pair {|k,v| args[k] = 0 unless v} 
			super(args[:b5], args[:b4], args[:b3], args[:b2], 
						args[:b1], args[:b0], args[:local], args[:multicast], 
						args[:oui])
		end

		# Returns the object in string form.
		def to_s
			byte = 0
			byte += 0b10000000 if b5.to_i == 1
			byte += 0b01000000 if b4.to_i == 1
			byte += 0b00100000 if b3.to_i == 1
			byte += 0b00010000 if b2.to_i == 1
			byte += 0b00001000 if b1.to_i == 1
			byte += 0b00000100 if b0.to_i == 1
			byte += 0b00000010 if local.to_i == 1
			byte += 0b00000001 if multicast.to_i == 1
			[byte,oui].pack("Cn")
		end

		# Reads a string to populate the object.
		def read(str)
			force_binary(str)
			return self if str.nil?
			if 1.respond_to? :ord
				byte = str[0].ord
			else
				byte = str[0]
			end
			self[:b5] =        byte & 0b10000000 == 0b10000000 ? 1 : 0
			self[:b4] =        byte & 0b01000000 == 0b01000000 ? 1 : 0
			self[:b3] =        byte & 0b00100000 == 0b00100000 ? 1 : 0
			self[:b2] =        byte & 0b00010000 == 0b00010000 ? 1 : 0
			self[:b1] =        byte & 0b00001000 == 0b00001000 ? 1 : 0
			self[:b0] =        byte & 0b00000100 == 0b00000100 ? 1 : 0
			self[:local] =     byte & 0b00000010 == 0b00000010 ? 1 : 0
			self[:multicast] = byte & 0b00000001 == 0b00000001 ? 1 : 0
			self[:oui] =       str[1,2].unpack("n").first
			self
		end

	end

  # EthNic is the Network Interface Controler portion of a MAC address, used in EthHeader.
	#
	# ==== Header Definition
	#
	#  Fixnum :n1
	#  Fixnum :n2
	#  Fixnum :n3
	#
	class EthNic < Struct.new(:n0, :n1, :n2)

		# EthNic does not enjoy StructFu typing.
		def initialize(args={})
			args.each_pair {|k,v| args[k] = 0 unless v} 
			super(args[:n0], args[:n1], args[:n2])
		end

		# Returns the object in string form.
		def to_s
			[n0,n1,n2].map {|x| x.to_i}.pack("C3")
		end
		
		# Reads a string to populate the object.
		def read(str)
			force_binary(str)
			return self if str.nil?
			self[:n0], self[:n1], self[:n2] = str[0,3].unpack("C3")
			self
		end

	end

	# EthMac is the combination of an EthOui and EthNic, used in EthHeader.
	#
	# ==== Header Definition
	#
	#   EthOui :oui  # See EthOui
	#   EthNic :nic  # See EthNic
	class EthMac < Struct.new(:oui, :nic)

		def initialize(args={})
			super(
			EthOui.new.read(args[:oui]),
			EthNic.new.read(args[:nic]))
		end

		# Returns the object in string form.
		def to_s
			"#{self[:oui]}#{self[:nic]}"
		end

		# Reads a string to populate the object.
		def read(str)
			force_binary(str)
			return self if str.nil?
			self.oui.read str[0,3]
			self.nic.read str[3,3]
			self
		end

	end

	# EthHeader is a complete Ethernet struct, used in EthPacket. 
	# It's the base header for all other protocols, such as IPHeader, 
	# TCPHeader, etc. 
	#
	# For more on the construction on MAC addresses, see 
	# http://en.wikipedia.org/wiki/MAC_address
	#
	# TODO: Need to come up with a good way of dealing with vlan
	# tagging. Having a usually empty struct member seems weird,
	# but there may not be another way to do it if I want to preserve
	# the Eth-ness of vlan-tagged 802.1Q packets. Also, may as well
	# deal with 0x88a8 as well (http://en.wikipedia.org/wiki/802.1ad)
	#
	# ==== Header Definition
	#
	#  EthMac  :eth_dst                     # See EthMac
	#  EthMac  :eth_src                     # See EthMac
	#  Int16   :eth_proto, Default: 0x8000  # IP 0x0800, Arp 0x0806
	#  String  :body
	class EthHeader < Struct.new(:eth_dst, :eth_src, :eth_proto, :body)
		include StructFu

		def initialize(args={})
			super(
				EthMac.new.read(args[:eth_dst]),
				EthMac.new.read(args[:eth_src]),
				Int16.new(args[:eth_proto] || 0x0800),
				StructFu::String.new.read(args[:body])
			)
		end

		# Setter for the Ethernet destination address.
		def eth_dst=(i); typecast(i); end
		# Getter for the Ethernet destination address.
		def eth_dst; self[:eth_dst].to_s; end
		# Setter for the Ethernet source address.
		def eth_src=(i); typecast(i); end
		# Getter for the Ethernet source address.
		def eth_src; self[:eth_src].to_s; end
		# Setter for the Ethernet protocol number.
		def eth_proto=(i); typecast(i); end
		# Getter for the Ethernet protocol number.
		def eth_proto; self[:eth_proto].to_i; end

		# Returns the object in string form.
		def to_s
			self.to_a.map {|x| x.to_s}.join
		end

		# Reads a string to populate the object.
		def read(str)
			force_binary(str)
			return self if str.nil?
			self[:eth_dst].read str[0,6]
			self[:eth_src].read str[6,6]
			self[:eth_proto].read str[12,2]
			self[:body].read str[14,str.size]
			self
		end

		# Converts a readable MAC (11:22:33:44:55:66) to a binary string. 
		# Readable MAC's may be split on colons, dots, spaces, or underscores.
		#
		# irb> PacketFu::EthHeader.mac2str("11:22:33:44:55:66")
		#
		# #=> "\021\"3DUf"
		def self.mac2str(mac)
			if mac.split(/[:\x2d\x2e\x5f]+/).size == 6
				ret =	mac.split(/[:\x2d\x2e\x20\x5f]+/).collect {|x| x.to_i(16)}.pack("C6")
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
		def self.str2mac(mac='')
			if mac.to_s.size == 6 && mac.kind_of?(::String)
				ret = mac.unpack("C6").map {|x| sprintf("%02x",x)}.join(":")
			end
		end

		# Sets the source MAC address in a more readable way.
		def eth_saddr=(mac)
			mac = EthHeader.mac2str(mac)
			self[:eth_src].read mac
			self[:eth_src]
		end

		# Gets the source MAC address in a more readable way. 
		def eth_saddr
			EthHeader.str2mac(self[:eth_src].to_s)
		end

		# Set the destination MAC address in a more readable way.
		def eth_daddr=(mac)
			mac = EthHeader.mac2str(mac)
			self[:eth_dst].read mac
			self[:eth_dst]
		end

		# Gets the destination MAC address in a more readable way. 
		def eth_daddr
			EthHeader.str2mac(self[:eth_dst].to_s)
		end

		# Readability aliases

		alias :eth_dst_readable :eth_daddr
		alias :eth_src_readable :eth_saddr

		def eth_proto_readable
			"0x%04x" % eth_proto
		end

	end

	# EthPacket is used to construct Ethernet packets. They contain an
	# Ethernet header, and that's about it.
	#
	# == Example
	#
	#   require 'packetfu'
	#   eth_pkt = PacketFu::EthPacket.new
	#   eth_pkt.eth_saddr="00:1c:23:44:55:66"
	#   eth_pkt.eth_daddr="00:1c:24:aa:bb:cc"
	#
	#   eth_pkt.to_w('eth0') # Inject on the wire. (require root)
	#
	class	EthPacket < Packet
		attr_accessor :eth_header

		def self.can_parse?(str)
			# XXX Temporary fix. Need to extend the EthHeader class to handle more.
			valid_eth_types = [0x0800, 0x0806, 0x86dd]
			return false unless str.size >= 14
			type = str[12,2].unpack("n").first rescue nil
			return false unless valid_eth_types.include? type
			true
		end

		def read(str=nil,args={})
			raise "Cannot parse `#{str}'" unless self.class.can_parse?(str)
			@eth_header.read(str)
			super(args)
			return self
		end

		# Does nothing, really, since there's no length or
		# checksum to calculate for a straight Ethernet packet.
		def recalc(args={})
			@headers[0].inspect
		end

		def initialize(args={})
			@eth_header = EthHeader.new(args).read(args[:eth])
			@headers = [@eth_header]
			super
		end

	end

end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
