# -*- coding: binary -*-
module PacketFu

	# UDPHeader is a complete UDP struct, used in UDPPacket. Many Internet-critical protocols
	# rely on UDP, such as DNS and World of Warcraft.
	#
	# For more on UDP packets, see http://www.networksorcery.com/enp/protocol/udp.htm
	#
	# ==== Header Definition
	#  Int16   :udp_src
	#  Int16   :udp_dst
	#  Int16   :udp_len  Default: calculated
	#  Int16   :udp_sum  Default: 0. Often calculated. 
	#  String  :body
	class UDPHeader < Struct.new(:udp_src, :udp_dst, :udp_len, :udp_sum, :body)

		include StructFu

		def initialize(args={})
			super(
				Int16.new(args[:udp_src]),
				Int16.new(args[:udp_dst]),
				Int16.new(args[:udp_len] || udp_calc_len),
				Int16.new(args[:udp_sum]),
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
			self[:udp_src].read(str[0,2])
			self[:udp_dst].read(str[2,2])
			self[:udp_len].read(str[4,2])
			self[:udp_sum].read(str[6,2])
			self[:body].read(str[8,str.size])
			self
		end

		# Setter for the UDP source port.
		def udp_src=(i); typecast i; end
		# Getter for the UDP source port.
		def udp_src; self[:udp_src].to_i; end
		# Setter for the UDP destination port.
		def udp_dst=(i); typecast i; end
		# Getter for the UDP destination port.
		def udp_dst; self[:udp_dst].to_i; end
		# Setter for the length field. Usually should be recalc()'ed instead.
		def udp_len=(i); typecast i; end
		# Getter for the length field.
		def udp_len; self[:udp_len].to_i; end
		# Setter for the checksum. Usually should be recalc()'ed instad.
		def udp_sum=(i); typecast i; end
		# Getter for the checksum.
		def udp_sum; self[:udp_sum].to_i; end

		# Returns the true length of the UDP packet.
		def udp_calc_len
			body.to_s.size + 8
		end

		# Recalculates calculated fields for UDP.
		def udp_recalc(args=:all)
			arg = arg.intern if arg.respond_to? :intern
			case args
			when :udp_len
				self.udp_len = udp_calc_len
			when :all
				self.udp_recalc(:udp_len)
			else
				raise ArgumentError, "No such field `#{arg}'"
			end
		end

		# Equivalent to udp_src.to_i
		def udp_sport
			self.udp_src
		end

		# Equivalent to udp_src=
		def udp_sport=(arg)
			self.udp_src=(arg)
		end

		# Equivalent to udp_dst
		def udp_dport
			self.udp_dst
		end
		
		# Equivalent to udp_dst=
		def udp_dport=(arg)
			self.udp_dst=(arg)
		end

		# Readability aliases

		def udp_sum_readable
			"0x%04x" % udp_sum
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

		def self.can_parse?(str)
			return false unless str.size >= 28
			return false unless EthPacket.can_parse? str
			return false unless IPPacket.can_parse? str
			return false unless str[23,1] == "\x11"
			return true
		end

		def read(str=nil, args={})
			raise "Cannot parse `#{str}'" unless self.class.can_parse?(str)
			@eth_header.read(str)
			@ip_header.read(str[14,str.size])
			@eth_header.body = @ip_header
			if args[:strip]
				udp_len = str[16,2].unpack("n")[0] - 20
				@udp_header.read(str[14+(@ip_header.ip_hlen),udp_len])
			else
				@udp_header.read(str[14+(@ip_header.ip_hlen),str.size])
			end
			@ip_header.body = @udp_header
			super(args)
			self
		end

		def initialize(args={})
			@eth_header = EthHeader.new(args).read(args[:eth])
			@ip_header = IPHeader.new(args).read(args[:ip])
			@ip_header.ip_proto=0x11
			@udp_header = UDPHeader.new(args).read(args[:icmp])
			@ip_header.body = @udp_header
			@eth_header.body = @ip_header
			@headers = [@eth_header, @ip_header, @udp_header]
			super
			udp_calc_sum
		end

		# udp_calc_sum() computes the UDP checksum, and is called upon intialization. 
		# It usually should be called just prior to dropping packets to a file or on the wire. 
		def udp_calc_sum
			# This is /not/ delegated down to @udp_header since we need info
			# from the IP header, too.
			checksum = (ip_src.to_i >> 16)
			checksum += (ip_src.to_i & 0xffff)
			checksum += (ip_dst.to_i >> 16)
			checksum += (ip_dst.to_i & 0xffff)
			checksum += 0x11
			checksum += udp_len.to_i
			checksum += udp_src.to_i
			checksum += udp_dst.to_i
			checksum += udp_len.to_i
			if udp_len.to_i >= 8
				# For IP trailers. This isn't very reliable. :/
				real_udp_payload = payload.to_s[0,(udp_len.to_i-8)] 
			else
				# I'm not going to mess with this right now.
				real_udp_payload = payload 
			end
			chk_payload = (real_udp_payload.size % 2 == 0 ? real_udp_payload : real_udp_payload + "\x00")
			chk_payload.unpack("n*").each {|x| checksum = checksum+x}
			checksum = checksum % 0xffff
			checksum = 0xffff - checksum
			checksum == 0 ? 0xffff : checksum
			@udp_header.udp_sum = checksum
		end

		# udp_recalc() recalculates various fields of the UDP packet. Valid arguments are:
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
		def peek_format
			peek_data = ["U  "]
			peek_data << "%-5d" % self.to_s.size
			peek_data << "%-21s" % "#{self.ip_saddr}:#{self.udp_sport}"
			peek_data << "->"
			peek_data << "%21s" % "#{self.ip_daddr}:#{self.udp_dport}"
			peek_data << "%23s" % "I:"
			peek_data << "%04x" % self.ip_id
			peek_data.join
		end

	end

end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
