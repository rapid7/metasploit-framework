
module PacketFu

	# ICMPHeader is a complete ICMP struct, used in ICMPPacket. ICMP is typically used for network
	# administration and connectivity testing.
	#
	# For more on ICMP packets, see http://www.networksorcery.com/enp/protocol/icmp.htm
	# 
	# ==== Header Definition
	#
	#   uint8     :icmp_type
	#   uint8     :icmp_code
	#   uint16be  :icmp_sum,  :initial_value => lambda { icmp_calc_sum }
	#   rest      :body
		
	class ICMPHeader < BinData::MultiValue
		uint8			:icmp_type
		uint8			:icmp_code
		uint16be	:icmp_sum,	:initial_value => lambda { icmp_calc_sum }
		rest			:body
		
		def icmp_calc_sum
			checksum = (icmp_type << 8)	+ icmp_code
			chk_body = (body.size % 2 == 0 ? body : body + "\x00")
			chk_body.scan(/[\x00-\xff]{2}/).collect { |x| (x[0] << 8) + x[1] }.each { |y| checksum += y }
			checksum = checksum % 0xffff
			checksum = 0xffff - checksum
			checksum == 0 ? 0xffff : checksum
		end
		
		def icmp_recalc(arg=:all)
			case arg.intern
			when :icmp_sum
				self.icmp_sum=icmp_calc_sum
			when :all
				self.icmp_sum=icmp_calc_sum
			else
				raise ArgumentError, "No such field `#{arg}'"
			end
		end

	end

	# ICMPPacket is used to construct ICMP Packets. They contain an EthHeader, an IPHeader, and a ICMPHeader.
	#
	# == Example
	#
	#  icmp_pkt.new
	#  icmp_pkt.icmp_type = 8
	#  icmp_pkt.icmp_code = 0
	#  icmp_pkt.payload = "ABC, easy as 123. As simple as do-re-mi. ABC, 123, baby, you and me!"
	#
	#  icmp_pkt.ip_saddr="1.2.3.4"
	#  icmp_pkt.ip_daddr="5.6.7.8"
	#
	#  icmp_pkt.recalc	
	#  icmp_pkt.to_f('/tmp/icmp.pcap')
	#
	# == Parameters
	#
	#  :eth
	#   A pre-generated EthHeader object.
	#  :ip
	#   A pre-generated IPHeader object.
	#  :flavor
	#   TODO: Sets the "flavor" of the ICMP packet. Pings, in particular, often betray their true
	#   OS.
	#  :config
	#   A hash of return address details, often the output of Utils.whoami?
	class ICMPPacket < Packet

		attr_accessor :eth_header, :ip_header, :icmp_header

		def ethernet?; true; end
		def ip?;   true; end
		def icmp?; true; end
				
		def initialize(args={})
			@eth_header = 	(args[:eth] || EthHeader.new)
			@ip_header 	= 	(args[:ip]	|| IPHeader.new)
			@icmp_header = 	(args[:icmp] || ICMPHeader.new)

			@ip_header.body = @icmp_header
			@eth_header.body = @ip_header

			@headers = [@eth_header, @ip_header, @icmp_header]
			super
		end

		# Peek provides summary data on packet contents.
		def peek(args={})
			peek_data = ["C "] # I is taken by IP
			peek_data << "%-5d" % self.to_s.size
			type = case self.icmp_type
						 when 8
							 "ping"
						 when 0
							 "pong"
						 else
							 "%02x-%02x" % [self.icmp_type, self.icmp_code]
						 end
			peek_data << "%-21s" % "#{self.ip_saddr}:#{type}"
			peek_data << "->"
			peek_data << "%21s" % "#{self.ip_daddr}"
			peek_data << "%23s" % "I:"
			peek_data << "%04x" % self.ip_id
			peek_data.join
		end
	end

end # module PacketFu