
module PacketFu

	# UDPHeader is a complete UDP struct, used in UDPPacket. Many Internet-critical protocols
	# rely on UDP, such as DNS and World of Warcraft.
	#
	# For more on UDP packets, see http://www.networksorcery.com/enp/protocol/udp.htm
	#
	# ==== Header Definition
	#  uint16be  :udp_src
	#  uint16be  :udp_dst
	#  uint16be  :udp_len,  :initial_value => lambda {udp_calc_len}
	#  uint16be  :udp_sum,  :initial_value =>  0                    # Checksum off
	#  rest      :body
 class UDPHeader < BinData::MultiValue
		uint16be	:udp_src
		uint16be	:udp_dst
		uint16be	:udp_len,	:initial_value => lambda {udp_calc_len}
		uint16be	:udp_sum,	:initial_value =>  0 # Checksum off
		rest			:body

		# Returns the true length of the UDP packet.
		def udp_calc_len
			body.to_s.size + 8
		end

		# Recalculates calculated fields for UDP.
		def udp_recalc(args=:all)
			case args
			when :udp_len
				self.udp_len = udp_calc_len
			when :all
				self.udp_recalc(:udp_len)
			else
				raise ArgumentError, "No such field `#{arg}'"
			end
		end

	end

	# UDPPacket is used to construct UDP Packets. They contain an EthHeader, an IPHeader, and a UDPHeader.
	#
	# == Example
	#
	#   udp_pkt = PacketFu::UDPPacket.new
	#   udp_pkt.udp_src=rand(0xffff-1024) + 1024
	#   udp_pkt.udp_dst=53
	# 
	#   udp_pkt.ip_saddr="1.2.3.4"
	#   udp_pkt.ip_daddr="10.20.30.40"
	#
	#   udp_pkt.recalc
	#   udp_pkt.to_f('/tmp/udp.pcap')
	#
	# == Parameters
	#
	#  :eth
	#    A pre-generated EthHeader object.
	#  :ip
	#    A pre-generated IPHeader object.
	#  :flavor
	#    TODO: Sets the "flavor" of the UDP packet. UDP packets don't tend have a lot of
	#    flavor, but their underlying ip headers do.
	#  :config
	#   A hash of return address details, often the output of Utils.whoami?
	class UDPPacket < Packet

		attr_accessor :eth_header, :ip_header, :udp_header
		
		def ethernet?; true; end
		def ip?;  true; end
		def udp?; true; end
				
		def initialize(args={})
			@eth_header = 	(args[:eth] || EthHeader.new)
			@ip_header 	= 	(args[:ip]	|| IPHeader.new)
			@udp_header = 	(args[:udp] || UDPHeader.new)

			@ip_header.body = @udp_header
			@eth_header.body = @ip_header
			@headers = [@eth_header, @ip_header, @udp_header]

			@ip_header.ip_proto=0x11
			super
			udp_calc_sum
		end

		# udp_calc_sum() computes the TCP checksum, and is called upon intialization. 
		# It usually should be called just prior to dropping packets to a file or on the wire. 
		def udp_calc_sum
			# This is /not/ delegated down to @udp_header since we need info
			# from the IP header, too.
			checksum = (ip_src.to_i >> 16)
			checksum += (ip_src.to_i & 0xffff)
			checksum += (ip_dst.to_i >> 16)
			checksum += (ip_dst.to_i & 0xffff)
			checksum += 0x11
			checksum += udp_len
			checksum += udp_src
			checksum += udp_dst
			checksum += udp_len
			if udp_len >= 8
				real_udp_payload = payload[0,(udp_len-8)] # For IP trailers. This isn't very reliable, though. :/
			else
				real_udp_payload = payload # I'm not going to mess with this right now.
			end
			chk_payload = (real_udp_payload.size % 2 == 0 ? real_udp_payload : real_udp_payload + "\x00")
			chk_payload.scan(/[\x00-\xff]{2}/).collect { |x| (x[0] << 8) + x[1] }.each { |y| checksum += y}
			checksum = checksum % 0xffff
			checksum = 0xffff - checksum
			checksum == 0 ? 0xffff : checksum
			@udp_header.udp_sum = checksum
		end

		# udp_recalc() recalculates various fields of the TCP packet. Valid arguments are:
		#
		#   :all
		#     Recomputes all calculated fields.
		#   :udp_sum
		#     Recomputes the UDP checksum.
		#   :udp_len
		#     Recomputes the UDP length.
		def udp_recalc(args=:all)
			case args
			when :udp_len
				@udp_header.udp_recalc
			when :udp_sum
				udp_calc_sum
			when :all
				@udp_header.udp_recalc
				udp_calc_sum
			else
				raise ArgumentError, "No such field `#{arg}'"
			end
		end

		# Peek provides summary data on packet contents.
		def peek(args={})
			peek_data = ["U "]
			peek_data << "%-5d" % self.to_s.size
			peek_data << "%-21s" % "#{self.ip_saddr}:#{self.udp_src}"
			peek_data << "->"
			peek_data << "%21s" % "#{self.ip_daddr}:#{self.udp_dst}"
			peek_data << "%23s" % "I:"
			peek_data << "%04x" % self.ip_id
			peek_data.join
		end

	end

end # module PacketFu