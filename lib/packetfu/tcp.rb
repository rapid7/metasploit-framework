require 'packetfu/tcpopts'
module PacketFu

	# Implements the Explict Congestion Notification for TCPHeader.
	#
	# ==== Header Definition
	#
	#
	#  bit1  :n
	#  bit1  :c
	#  bit1  :e
	class TcpEcn < BinData::MultiValue
		bit1	:n
		bit1	:c
		bit1	:e

		# Returns the TcpEcn field as an integer.
		def to_i
			(n << 2) + (c << 1) + e
		end
	end

	# Implements flags for TCPHeader.
	#
	# ==== Header Definition
	#
	#  bit1  :urg
	#  bit1  :ack
	#  bit1  :psh
	#  bit1  :rst
	#  bit1  :syn
	#  bit1  :fin
	class TcpFlags < BinData::MultiValue
		bit1	:urg
		bit1	:ack
		bit1	:psh
		bit1	:rst
		bit1	:syn
		bit1	:fin

		# Returns the TcpFlags as an integer.
		def to_i
			(urg << 5) + (ack << 4) + (psh << 3) + (rst << 2) + (syn << 1) + fin
		end
	end

	# TCPHeader is a complete TCP struct, used in TCPPacket. Most IP traffic is TCP-based, by
	# volume.
	#
	# For more on TCP packets, see http://www.networksorcery.com/enp/protocol/tcp.htm
	#
	# ==== Header Definition
	# 
	#   uint16be  :tcp_src,  :initial_value => lambda {tcp_calc_src}
	#   uint16be  :tcp_dst
	#   uint32be  :tcp_seq,  :initial_value => lambda {tcp_calc_seq}
	#   uint32be  :tcp_ack
	#   bit4      :tcp_hlen, :initial_value => 5       # Must recalc as options are set. 
	#   bit3      :tcp_reserved
	#   tcp_ecn   :tcp_ecn
	#   tcp_flags :tcp_flags
	#   uint16be  :tcp_win,  :initial_value => 0x4000 # WinXP's default syn packet
	#   uint16be  :tcp_sum,  :initial_value => 0      # Must set this upon generation.
	#   uint16be  :tcp_urg
	#   string    :tcp_opts
	#   rest      :body
	#
	# See also TcpEcn, TcpFlags, TcpOpts
	class TCPHeader < BinData::MultiValue

		uint16be	:tcp_src,		:initial_value => lambda {tcp_calc_src} 
		uint16be	:tcp_dst
		uint32be	:tcp_seq,		:initial_value => lambda {tcp_calc_seq}
		uint32be	:tcp_ack
		bit4			:tcp_hlen,	:initial_value => 5 # Must recalc as options are set. 
		bit3			:tcp_reserved
		tcp_ecn		:tcp_ecn
		tcp_flags	:tcp_flags
		uint16be	:tcp_win,		:initial_value => 0x4000 # WinXP's default syn packet
		uint16be	:tcp_sum, 	:initial_value =>	0 # Must set this upon generation.
		uint16be	:tcp_urg
		string		:tcp_opts
		rest			:body

		# Create a new TCPHeader object, and intialize with a random sequence number. 
		def initialize(args={})
			@random_seq = rand(0xffffffff)
			@random_src = rand_port
			super
		end

		attr_accessor :flavor

		# tcp_calc_hlen adjusts the header length to account for tcp_opts. Note
		# that if tcp_opts does not fall on a 32-bit boundry, tcp_calc_hlen will
		# additionally pad the option string with nulls. Most stacks avoid this 
		# eventuality by padding with NOP options at OS-specific points in the 
		# option field. The practical effect of this is, you should tcp_calc_hlen
		# only when all the options are already set; otherwise, additional options
		# will be lost to the reciever as \x00 is an EOL option. Additionally,
		# (and this is almost certainly a bug), there is no sanity checking to
		# ensure the final tcp_opts value is 44 bytes or less (any more will bleed
		# over into the tcp payload). You are forewarned!
		#
		# If you would like to craft specifically malformed packets with 
		# nonsense lengths of opts fields, you should avoid tcp_calc_hlen 
		# altogether, and simply set the values for tcp_hlen and tcp_opts manually.
		def tcp_calc_hlen
			pad = (self.tcp_opts.to_s.size % 4)
			if (pad > 0)
				self.tcp_opts += ("\x00" * pad)
			end
			self.tcp_hlen = ((20 + self.tcp_opts.to_s.size) / 4)
		end

		def tcp_calc_seq
			@random_seq
		end

		def tcp_calc_src
			@random_src
		end

		# Generates a random high port. This is affected by packet flavor.
		def rand_port
			rand(0xffff - 1025) + 1025
		end

		# Returns the actual length of the TCP options.
		def tcp_opts_len
			tcp_opts.to_s.size * 4
		end

		# Returns a more readable option list. Note, it can lack fidelity on bad option strings.
		# For more on TCP options, see the TcpOpts class.
		def tcp_options
			TcpOpts.decode(self.tcp_opts)
		end

		# Allows a more writable version of TCP options. 
		# For more on TCP options, see the TcpOpts class.
		def tcp_options=(arg)
			self.tcp_opts=TcpOpts.encode(arg) 
		end

		# Equivalent to tcp_src
		def tcp_sport
			self.tcp_src
		end

		# Equivalent to tcp_src=
		def tcp_sport=(arg)
			self.tcp_src=(arg)
		end

		# Equivalent to tcp_dst
		def tcp_dport
			self.tcp_dst
		end
		
		# Equivalent to tcp_dst=
		def tcp_dport=(arg)
			self.tcp_dst=(arg)
		end

		# Recalculates calculated fields for TCP (except checksum which is at the Packet level).
		def tcp_recalc(arg=:all)
			case arg
			when :tcp_hlen
				tcp_calc_hlen
			when :tcp_src
				@random_tcp_src = rand_port
			when :tcp_sport
				@random_tcp_src = rand_port
			when :tcp_seq
				@random_tcp_seq = rand(0xffffffff) 
			when :all
				tcp_calc_hlen
				@random_tcp_src = rand_port
				@random_tcp_seq = rand(0xffffffff) 
			else
				raise ArgumentError, "No such field `#{arg}'"
			end
		end

	end

	# TCPPacket is used to construct TCP packets. They contain an EthHeader, an IPHeader, and a TCPHeader.
	#
	# == Example
	#
  #    tcp_pkt = PacketFu::TCPPacket.new
  #    tcp_pkt.tcp_flags.syn=1
  #    tcp_pkt.tcp_dst=80
  #    tcp_pkt.tcp_win=5840
  #    tcp_pkt.tcp_options="mss:1460,sack.ok,ts:#{rand(0xffffffff)};0,nop,ws:7"
	#
  #    tcp_pkt.ip_saddr=[rand(0xff),rand(0xff),rand(0xff),rand(0xff)].join('.')
  #    tcp_pkt.ip_daddr=[rand(0xff),rand(0xff),rand(0xff),rand(0xff)].join('.')
	#
  #    tcp_pkt.recalc
  #    tcp_pkt.to_f('/tmp/tcp.pcap')
	#
	# == Parameters
	#  :eth
	#    A pre-generated EthHeader object.
	#  :ip
	#    A pre-generated IPHeader object.
	#  :flavor
	#    TODO: Sets the "flavor" of the TCP packet. This will include TCP options and the initial window
	#    size, per stack. There is a lot of variety here, and it's one of the most useful methods to
	#    remotely fingerprint devices. :flavor will span both ip and tcp for consistency.
	#   :type
	#    TODO: Set up particular types of packets (syn, psh_ack, rst, etc). This can change the initial flavor.
	#  :config
	#   A hash of return address details, often the output of Utils.whoami?
	class TCPPacket < Packet

		attr_accessor :eth_header, :ip_header, :tcp_header, :headers

		def ethernet?; true; end
		def ip?;  true; end
		def tcp?; true; end
						
		def initialize(args={})
			@eth_header = 	(args[:eth] || EthHeader.new)
			@ip_header 	= 	(args[:ip]	|| IPHeader.new)
			@tcp_header = 	(args[:tcp] || TCPHeader.new)
			@tcp_header.flavor = args[:flavor].to_s.downcase

			@ip_header.body = @tcp_header
			@eth_header.body = @ip_header
			@headers = [@eth_header, @ip_header, @tcp_header]

			@ip_header.ip_proto=0x06
			super
			if args[:flavor]
				tcp_calc_flavor(@tcp_header.flavor)
			else
				tcp_calc_sum
			end
		end

		# Sets the correct flavor for TCP Packets. Recognized flavors are:
		#   windows, linux, freebsd
		def tcp_calc_flavor(str)
			ts_val = Time.now.to_i + rand(0x4fffffff)
			ts_sec = rand(0xffffff)
			case @tcp_header.flavor = str.to_s.downcase
			when "windows" # WinXP's default syn
				@tcp_header.tcp_win = 0x4000
				@tcp_header.tcp_options="MSS:1460,NOP,NOP,SACK.OK"
				@tcp_header.tcp_src = rand(5000 - 1026) + 1026
				@ip_header.ip_ttl = 64
			when "linux" # Ubuntu Linux 2.6.24-19-generic default syn
				@tcp_header.tcp_win = 5840
				@tcp_header.tcp_options="MSS:1460,SACK.OK,TS:#{ts_val};0,NOP,WS:7"
				@tcp_header.tcp_src = rand(61_000 - 32_000) + 32_000
				@ip_header.ip_ttl = 64
			when "freebsd" # Freebsd
				@tcp_header.tcp_win = 0xffff
				@tcp_header.tcp_options="MSS:1460,NOP,WS:3,NOP,NOP,TS:#{ts_val};#{ts_sec},SACK.OK,EOL,EOL"
				@ip_header.ip_ttl = 64
			else
				@tcp_header.tcp_options="MSS:1460,NOP,NOP,SACK.OK"
			end
			tcp_calc_sum
		end

		# tcp_calc_sum() computes the TCP checksum, and is called upon intialization. It usually
		# should be called just prior to dropping packets to a file or on the wire.
		#--
		# This is /not/ delegated down to @tcp_header since we need info
		# from the IP header, too.
		#++
		def tcp_calc_sum
			checksum =  (ip_src.to_i >> 16)
			checksum += (ip_src.to_i & 0xffff)
			checksum += (ip_dst.to_i >> 16)
			checksum += (ip_dst.to_i & 0xffff)
			checksum += 0x06 # TCP Protocol.
			checksum +=	(ip_len.to_i - ((ip_hl.to_i) * 4))
			checksum += tcp_src
			checksum += tcp_dst
			checksum += (tcp_seq.to_i >> 16)
			checksum += (tcp_seq.to_i & 0xffff)
			checksum += (tcp_ack.to_i >> 16)
			checksum += (tcp_ack.to_i & 0xffff)
			checksum += ((tcp_hlen << 12) + 
									 (tcp_reserved << 9) + 
									 (tcp_ecn.to_i << 6) + 
									 tcp_flags.to_i
									)
			checksum += tcp_win
			checksum += tcp_urg

			chk_tcp_opts = (tcp_opts.to_s.size % 2 == 0 ? tcp_opts.to_s : tcp_opts.to_s + "\x00") 
			chk_tcp_opts.scan(/[\x00-\xff]{2}/).collect { |x| (x[0] << 8) + x[1] }.each { |y| checksum += y}
			if (ip_len - ((ip_hl + tcp_hlen) * 4)) >= 0
				real_tcp_payload = payload[0,( ip_len - ((ip_hl + tcp_hlen) * 4) )] # Can't forget those pesky FCSes!
			else
				real_tcp_payload = payload # Something's amiss here so don't bother figuring out where the real payload is.
			end
			chk_payload = (real_tcp_payload.size % 2 == 0 ? real_tcp_payload : real_tcp_payload + "\x00") # Null pad if it's odd.
			chk_payload.scan(/[\x00-\xff]{2}/).collect { |x| (x[0] << 8) + x[1] }.each { |y| checksum += y}
			checksum = checksum % 0xffff
			checksum = 0xffff - checksum
			checksum == 0 ? 0xffff : checksum
			@tcp_header.tcp_sum = checksum
		end

		# Recalculates various fields of the TCP packet.
		#
		# ==== Parameters
		#
		#   :all
		#     Recomputes all calculated fields.
		#   :tcp_sum
		#     Recomputes the TCP checksum.
		#   :tcp_hlen
		#     Recomputes the TCP header length. Useful after options are added.
		def tcp_recalc(arg=:all)
			case arg
			when :tcp_sum
				tcp_calc_sum
			when :tcp_hlen
				@tcp_header.tcp_recalc :tcp_hlen
			when :all
				@tcp_header.tcp_recalc :all
				tcp_calc_sum
			else
				raise ArgumentError, "No such field `#{arg}'"
			end
		end

		# Peek provides summary data on packet contents.
		def peek(args={})
			peek_data = ["T "]
			peek_data << "%-5d" % self.to_s.size
			peek_data << "%-21s" % "#{self.ip_saddr}:#{self.tcp_src}"
			peek_data << "->"
			peek_data << "%21s" % "#{self.ip_daddr}:#{self.tcp_dst}"
			flags = ' ['
			flags << (self.tcp_flags.urg.zero? ? "." : "U")
			flags << (self.tcp_flags.ack.zero? ? "." : "A")
			flags << (self.tcp_flags.psh.zero? ? "." : "P")
			flags << (self.tcp_flags.rst.zero? ? "." : "R")
			flags << (self.tcp_flags.syn.zero? ? "." : "S")
			flags << (self.tcp_flags.fin.zero? ? "." : "F")
			flags << '] '
			peek_data << flags
			peek_data << "S:"
			peek_data << "%08x" % self.tcp_seq
			peek_data << "|I:"
			peek_data << "%04x" % self.ip_id
			peek_data.join
		end

	end

end # module PacketFu