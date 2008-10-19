
module PacketFu

	# Octets implements the addressing scheme for IP.
	#
	# ==== Header Definition
	#
	#  uint8 :o1
	#  uint8 :o2
	#  uint8 :o3
	#  uint8 :o4
	class Octets < BinData::MultiValue
		uint8	:o1
		uint8	:o2
		uint8	:o3
		uint8	:o4

		# Returns an address in dotted-quad format.
		def to_x
			ip_str = [o1, o2, o3, o4].join('.')
			IPAddr.new(ip_str).to_s
		end

		# Returns an address in numerical format.
		def to_i
			ip_str = [o1, o2, o3, o4].join('.')
			IPAddr.new(ip_str).to_i
		end

		# Returns an address as an array of numbers.
		def to_ary
			[o1,o2,o3,o4]
		end

		alias to_a to_ary
	end

	# IPHeader is a complete IP struct, used in IPPacket. Most traffic on most networks today is IP-based.
	#
	# For more on IP packets, see http://www.networksorcery.com/enp/protocol/ip.htm
	#
	# ==== Header Definition
	#
	#   bit4     :ip_v,     :initial_value => 4
	#   bit4     :ip_hl,    :initial_value => 5
	#   uint8    :ip_tos,   :initial_value => 0                     # TODO: Break out the bits
	#   uint16be :ip_len,   :initial_value => lambda { ip_calc_len } 
	#   uint16be :ip_id,    :initial_value => lambda { ip_calc_id } # IRL, hardly random. 
	#   uint16be :ip_frag,  :initial_value => 0                     # TODO: Break out the bits
	#   uint8    :ip_ttl,   :initial_value => 0xff                  # Changes per flavor
	#   uint8    :ip_proto, :initial_value => 0x01                  # TCP: 0x06, UDP 0x11, ICMP 0x01
	#   uint16be :ip_sum,   :initial_value => lambda { ip_calc_sum }
	#   octets   :ip_src                                            # No value as this is a MultiValue
	#   octets   :ip_dst                                            # Ditto.
	#   rest     :body
	class IPHeader < BinData::MultiValue

		bit4 				:ip_v, 		:initial_value => 4
		bit4 				:ip_hl, 	:initial_value => 5
		uint8				:ip_tos,	:initial_value => 0 											# TODO: Break out the bits
		uint16be		:ip_len,	:initial_value => lambda { ip_calc_len }	
		uint16be		:ip_id,		:initial_value => lambda { ip_calc_id }	# IRL, hardly random. 
		uint16be		:ip_frag,	:initial_value => 0 											# TODO: Break out the bits
		uint8				:ip_ttl,	:initial_value => 0xff 										# Changes per flavor
		uint8				:ip_proto,:initial_value => 0x01 										# TCP: 0x06, UDP 0x11, ICMP 0x01
		uint16be		:ip_sum, 	:initial_value => lambda { ip_calc_sum }
		octets			:ip_src 																							# No value as this is a MultiValue
		octets			:ip_dst 																							# Ditto.
		rest				:body
		
		# Creates a new IPHeader object, and intialize with a random IPID. 
		def initialize(*args)
			@random_id = rand(0xffff)
			super
		end

		# Calulcate the true length of the packet.
		def ip_calc_len
			(ip_hl * 4) + body.to_s.length
		end

		# Calculate the true checksum of the packet.
		# (Yes, this is the long way to do it, but it's e-z-2-read for mathtards like me.)
		def ip_calc_sum
			checksum =  (((ip_v  <<  4) + ip_hl) << 8) +ip_tos
			checksum += ip_len
			checksum +=	ip_id
			checksum += ip_frag
			checksum +=	(ip_ttl << 8) + ip_proto
			checksum += (ip_src.to_i >> 16)
			checksum += (ip_src.to_i & 0xffff)
			checksum += (ip_dst.to_i >> 16)
			checksum += (ip_dst.to_i & 0xffff)
			checksum = checksum % 0xffff 
			checksum = 0xffff - checksum
			checksum == 0 ? 0xffff : checksum
		end

		# Retrieve the IP ID
		def ip_calc_id
			@random_id
		end

		# Sets a more readable IP address. If you wants to manipulate individual octets, 
		# (eg, for host scanning in one network), it would be better use ip_src.o1 through 
		# ip_src.o4 instead. 
		def ip_saddr=(addr)
			addr = IPHeader.octet_array(addr)
			ip_src.o1 = addr[0]
			ip_src.o2 = addr[1]
			ip_src.o3 = addr[2]
			ip_src.o4 = addr[3]
		end

		# Returns a more readable IP source address. 
		def ip_saddr
			[ip_src.o1,ip_src.o2,ip_src.o3,ip_src.o4].join('.')
		end

		# Sets a more readable IP address.
		def ip_daddr=(addr)
			addr = IPHeader.octet_array(addr)
			ip_dst.o1 = addr[0]
			ip_dst.o2 = addr[1]
			ip_dst.o3 = addr[2]
			ip_dst.o4 = addr[3]
		end
		
		# Returns a more readable IP destination address.
		def ip_daddr
			[ip_dst.o1,ip_dst.o2,ip_dst.o3,ip_dst.o4].join('.')
		end


		# Translate various formats of IPv4 Addresses to an array of digits.
		def self.octet_array(addr)
			if addr.class == String
				oa = addr.split('.').collect {|x| x.to_i}
			elsif addr.class == Fixnum
				oa = IPAddr.new(addr, Socket::AF_INET).to_s.split('.')
			elsif addr.class == Bignum
				oa = IPAddr.new(addr, Socket::AF_INET).to_s.split('.')
			elsif addr.class == Array
				oa = addr
			else
				raise ArgumentError, "IP Address should be a dotted quad string, an array of ints, or a bignum"
			end
		end

		# Recalculate the calculated IP fields. Valid arguments are:
		#   :all :ip_len :ip_sum :ip_id
		def ip_recalc(arg=:all)
			case arg
			when :ip_len
				self.ip_len=ip_calc_len
			when :ip_sum
				self.ip_sum=ip_calc_sum
			when :ip_id
				@random_id = rand(0xffff)
			when :all
				self.ip_id=		ip_calc_id
				self.ip_len=	ip_calc_len
				self.ip_sum=	ip_calc_sum
			else
				raise ArgumentError, "No such field `#{arg}'"
			end
		end
	end # class IPHeader

	# IPPacket is used to construct IP packets. They contain an EthHeader, an IPHeader, and usually
	# a transport-layer protocol such as UDPHeader, TCPHeader, or ICMPHeader.
	#
	# == Example
	#
	#   require 'packetfu'
	#   ip_pkt = PacketFu::IPPacket.new
	#   ip_pkt.ip_saddr="10.20.30.40"
	#   ip_pkt.ip_daddr="192.168.1.1"
	#   ip_pkt.ip_proto=1
	#   ip_pkt.ip_ttl=64
	#   ip_pkt.ip_payload="\x00\x00\x12\x34\x00\x01\x00\x01"+
	#     "Lovingly hand-crafted echo responses delivered directly to your door."
	#   ip_pkt.recalc 
	#   ip_pkt.to_f('/tmp/ip.pcap')
	#
	# == Parameters
	#
	#   :eth
	#     A pre-generated EthHeader object.
	#   :ip
	#     A pre-generated IPHeader object.
	#   :flavor
	#     TODO: Sets the "flavor" of the IP packet. This might include known sets of IP options, and
	#     certainly known starting TTLs.
	#   :config
	#     A hash of return address details, often the output of Utils.whoami?
	class IPPacket < Packet

		attr_accessor :eth_header, :ip_header

		def ethernet?; true; end
		def ip?;  true; end
		
		# Creates a new IPPacket object. 
		def initialize(args={})
			@eth_header = (args[:eth] || EthHeader.new)
			@ip_header 	= (args[:ip]	|| IPHeader.new)
			@eth_header.body=@ip_header

			@headers = [@eth_header, @ip_header]
			super

		end

		# Peek provides summary data on packet contents.
		def peek(args={})
			peek_data = ["I "]
			peek_data << "%-5d" % self.to_s.size
			peek_data << "%-21s" % "#{self.ip_saddr}"
			peek_data << "->"
			peek_data << "%21s" % "#{self.ip_daddr}"
			peek_data << "%23s" % "I:"
			peek_data << "%04x" % self.ip_id
			peek_data.join
		end

	end

end # module PacketFu