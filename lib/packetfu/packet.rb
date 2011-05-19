module PacketFu

	# Packet is the parent class of EthPacket, IPPacket, UDPPacket, TCPPacket, and all
	# other packets.
	class Packet
		attr_reader :flavor # Packet Headers are responsible for their own specific flavor methods.
		attr_accessor :headers # All packets have a header collection, useful for determining protocol trees.
		attr_accessor :iface # Default inferface to send packets to

		# Force strings into binary.
		def self.force_binary(str)
			str.force_encoding "binary" if str.respond_to? :force_encoding
		end

		# parse_app makes a valiant attempt at picking out particular applications (beyond
		# the transport layer). As of right now, this only accounts for HSRP. I don't really
		# intend to get very far with this because I need a better way to parse packets anyway --
		# each packet type (including application layers) should be responsible for their own
		# parsing rules. But, let's assume that'll never happen, so continue with this folly.
		#
		# This is an optional step, since it can lead to misidentified applications, depending
		# on the strategy used to pick out app layers. For example, we really shouldn't have
		# a rule that says that HTTP must be port 80, since it can easily be on 3128 or any
		# other arbitrary port. However, we can say with certainty that HSRP must be dst port
		# 1985, because that's what the RFC dictates.
		def self.parse_app(parsed_packet,packet)
			if parsed_packet.is_udp?
				# Figure out UDP protocols (DNS, DHCP, etc)
				# All HSRP is dst 224.0.0.2:1985 with a TTL of 1, so sayeth RFC 2281.
				if(
					parsed_packet.ip_ttl == 1 and
					parsed_packet.ip_dst == 0xe0000002 and
					parsed_packet.udp_dst == 1985
				)
					return HSRPPacket.new.read(packet)
				else
					return parsed_packet
				end
			elsif parsed_packet.is_tcp?
				# Figure out TCP protocols (HTTP, SSH, etc)
				return parsed_packet
			else
				# I don't know any others.
				return parsed_packet
			end
		end

		# Parse() creates the correct packet type based on the data, and returns the apporpiate
		# Packet subclass. 
		#
		# There is an assumption here that all incoming packets are either EthPacket
		# or InvalidPacket types.
		#
		# If application-layer parsing is /not/ desired, that should be indicated explicitly
		# with an argument of  :parse_app => false.
		#
		# New packet types should get an entry here. 
		def self.parse(packet,args={})
			parse_app = true if(args[:parse_app].nil? or args[:parse_app])
			force_binary(packet)
			if packet.size >= 14													# Min size for Ethernet. No check for max size, yet.
				case packet[12,2]														# Check the Eth protocol field.
				when "\x08\x00"															# It's IP.
					if 1.respond_to? :ord
						ipv = packet[14,1][0].ord >> 4
					else
						ipv = packet[14,1][0] >> 4
					end
					case ipv																	# Check the IP version field.
					when 4;				 														# It's IPv4.
						case packet[23,1]												# Check the IP protocol field.
						when "\x06"; p = TCPPacket.new					# Returns a TCPPacket.
						when "\x11"; p = UDPPacket.new					# Returns a UDPPacket.
						when "\x01"; p = ICMPPacket.new					# Returns an ICMPPacket.
						else; p = IPPacket.new									# Returns an IPPacket since we can't tell the transport layer.
						end
					else; p = IPPacket.new										# Returns an IPPacket of this crazy IP version.
					end
				when "\x08\x06"															# It's arp
					if packet.size >= 28											# Min size for complete arp
						p = ARPPacket.new
					else; p = EthPacket.new										# Returns an EthPacket since we can't deal with tiny arps.
					end
				when "\x86\xdd"															# It's IPv6
					if packet.size >= 54											# Min size for a complete IPv6 packet.
						p = IPv6Packet.new
					else; p = EthPacket.new										# Returns an EthPacket since we can't deal with tiny Ipv6.
					end
				else; p = EthPacket.new											# Returns an EthPacket since we can't tell the network layer.
				end
			else
				p = InvalidPacket.new												# Not the right size for Ethernet (jumbo frames are okay)
			end
			parsed_packet = p.read(packet,args)
			app_parsed_packet = parse_app ? parse_app(parsed_packet,packet) : nil
			return app_parsed_packet || parsed_packet
		end

		#method_missing() delegates protocol-specific field actions to the apporpraite
		#class variable (which contains the associated packet type)
		#This register-of-protocols style switch will work for the 
		#forseeable future (there aren't /that/ many packet types), and it's a handy
		#way to know at a glance what packet types are supported.
		def method_missing(sym, *args, &block)
			case sym.to_s
			when /^invalid_/
				@invalid_header.send(sym,*args)
			when /^eth_/
				@eth_header.send(sym,*args)
			when /^arp_/
				@arp_header.send(sym,*args)
			when /^ip_/
				@ip_header.send(sym,*args)
			when /^icmp_/
				@icmp_header.send(sym,*args)
			when /^udp_/
				@udp_header.send(sym,*args)
			when /^hsrp_/
				@hsrp_header.send(sym,*args)
			when /^tcp_/
				@tcp_header.send(sym,*args)
			when /^ipv6_/
				@ipv6_header.send(sym,*args)
			else
				raise NoMethodError, "Unknown method `#{sym}' for this packet object."
			end
		end
		
		def respond_to?(sym, include_private = false)
			if sym.to_s =~ /^(invalid|eth|arp|ip|icmp|udp|hsrp|tcp|ipv6)_/
				self.instance_variable_get("@#{$1}_header").respond_to? sym
			else
				super
			end
		end

		# Get the binary string of the entire packet.
		def to_s
			@headers[0].to_s
		end

		# In the event of no proper decoding, at least send it to the inner-most header.
		def write(io)
			@headers[0].write(io)
		end

		# Get the outermost payload (body) of the packet; this is why all packet headers
		# should have a body type.
		def payload
			@headers.last.body
		end

		# Set the outermost payload (body) of the packet.
		def payload=(args)
			@headers.last.body=(args)
		end

		# Converts a packet to libpcap format. Bit of a hack?
		def to_pcap(args={})
			p = PcapPacket.new(:endian => args[:endian],
												:timestamp => Timestamp.new.to_s,
												:incl_len => self.to_s.size,
												:orig_len => self.to_s.size,
												:data => self)
		end

		# Put the entire packet into a libpcap file. XXX: this is a
		# hack for now just to confirm that packets are getting created
		# correctly. Now with append! XXX: Document this!
		def to_f(filename=nil,mode='w')
			filename ||= 'out.pcap'
			mode = mode.to_s[0,1] + "b"
			raise ArgumentError, "Unknown mode: #{mode.to_s}" unless mode =~ /^[wa]/
			if(mode == 'w' || !(File.exists?(filename)))
				data = [PcapHeader.new, self.to_pcap].map {|x| x.to_s}.join
			else
				data = self.to_pcap
			end
			File.open(filename, mode) {|f| f.write data}
			return [filename, 1, data.size]
		end

		# Put the entire packet on the wire by creating a temporary PacketFu::Inject object.
		# TODO: Do something with auto-checksumming?
		def to_w(iface=nil)
			iface = iface || self.iface || PacketFu::Config.new.config[:iface]
			inj = PacketFu::Inject.new(:iface => iface)
			inj.array = [@headers[0].to_s]
			inj.inject
		end
		
		# Recalculates all the calcuated fields for all headers in the packet.
		# This is important since read() wipes out all the calculated fields
		# such as length and checksum and what all.
		def recalc(arg=:all)
			case arg
			when :ip
				ip_recalc(:all)
			when :icmp
				icmp_recalc(:all)
			when :udp
				udp_recalc(:all)
			when :tcp
				tcp_recalc(:all)
			when :all
				ip_recalc(:all) if @ip_header
				icmp_recalc(:all) if @icmp_header
				udp_recalc(:all) if @udp_header
				tcp_recalc(:all) if @tcp_header
			else
				raise ArgumentError, "Recalculating `#{arg}' unsupported. Try :all"
			end
			@headers[0]
		end

		# Read() takes (and trusts) the io input and shoves it all into a well-formed Packet.
		# Note that read is a destructive process, so any existing data will be lost.
		#
		# TODO: This giant if tree is a mess, and worse, is decieving. You need to define
		# actions both here and in parse(). All read() does is make a (good) guess as to
		# what @headers to expect, and reads data to them.
		#
		# To take strings and turn them into packets without knowing ahead of time what kind of
		# packet it is, use Packet.parse instead; parse() handles the figuring-out part.
		#
		# A note on the :strip => true argument: If :strip is set, defined lengths of data will
		# be believed, and any trailers (such as frame check sequences) will be chopped off. This
		# helps to ensure well-formed packets, at the cost of losing perhaps important FCS data.
		# 
		# If :strip is false, header lengths are /not/ believed, and all data will be piped in.
		# When capturing from the wire, this is usually fine, but recalculating the length before
		# saving or re-transmitting will absolutely change the data payload; FCS data will become
		# part of the TCP data as far as tcp_len is concerned. Some effort has been made to preserve
		# the "real" payload for the purposes of checksums, but currently, it's impossible to seperate
		# new payload data from old trailers, so things like pkt.payload += "some data" will not work
		# correctly.
		#
		# So, to summarize; if you intend to alter the data, use :strip. If you don't, don't. Also,
		# this is a horrid XXX hack. Stripping is useful (and fun!), but the default behavior really
		# should be to create payloads correctly, and /not/ treat extra FCS data as a payload.
		#
		# Update: This scheme is so lame. Need to fix. Seriously.
		# Update: still sucks. Really.
		def read(io,args={})
			begin
				if io.size >= 14
					@eth_header.read(io)
					eth_proto_num = io[12,2].unpack("n")[0]
					if eth_proto_num == 0x0800 # It's IP.
						if 1.respond_to? :ord
							ipv = io[14].ord 
						else
							ipv = io[14] 
						end
						ip_hlen=(ipv & 0x0f) * 4
						ip_ver=(ipv >> 4) # It's IPv4. Other versions, all bets are off!
						if ip_ver == 4
							ip_proto_num = io[23,1].unpack("C")[0]
							@ip_header.read(io[14,ip_hlen])
							if ip_proto_num == 0x06 # It's TCP.
								tcp_len = io[16,2].unpack("n")[0] - 20
								if args[:strip] # Drops trailers like frame check sequence (FCS). Often desired for cleaner packets.
									tcp_all = io[ip_hlen+14,tcp_len] # Believe the tcp_len value; chop off anything that's not in range.
								else
									tcp_all = io[ip_hlen+14,0xffff] # Don't believe the tcp_len value; suck everything up.
								end
								tcp_hlen =  ((tcp_all[12,1].unpack("C")[0]) >> 4) * 4
								if tcp_hlen.to_i >= 20
									@tcp_header.read(tcp_all)
									@ip_header.body = @tcp_header
								else # It's a TCP packet with an impossibly small hlen, so it can't be real TCP. Abort! Abort!
									@ip_header.body = io[16,io.size-16]
								end
							elsif ip_proto_num == 0x11 # It's UDP.
								udp_len = io[16,2].unpack("n")[0] - 20
								if args[:strip] # Same deal as with TCP. We might have stuff at the end of the packet that's not part of the payload.
									@udp_header.read(io[ip_hlen+14,udp_len]) 
								else # ... Suck it all up. BTW, this will change the lengths if they are ever recalc'ed. Bummer.
									@udp_header.read(io[ip_hlen+14,0xffff])
								end
								@ip_header.body = @udp_header
							elsif ip_proto_num == 1 # It's ICMP
								@icmp_header.read(io[ip_hlen+14,0xffff])
								@ip_header.body = @icmp_header
							else # It's an IP packet for a protocol we don't have a decoder for.
								@ip_header.body = io[16,io.size-16] 
							end
						else # It's not IPv4, so no idea what should come next. Just dump it all into an ip_header and ip payload.
							@ip_header.read(io[14,ip_hlen])
							@ip_header.body = io[16,io.size-16]
						end
						@eth_header.body = @ip_header
					elsif eth_proto_num == 0x0806 # It's ARP
						@arp_header.read(io[14,0xffff]) # You'll nearly have a trailer and you'll never know what size.
						@eth_header.body=@arp_header
						@eth_header.body
					elsif eth_proto_num == 0x86dd # It's IPv6
						@ipv6_header.read(io[14,0xffff])
						@eth_header.body=@ipv6_header
					else # It's an Ethernet packet for a protocol we don't have a decoder for
						@eth_header.body = io[14,io.size-14]
					end
					if (args[:fix] || args[:recalc])
						# Unfortunately, we cannot simply recalc with abandon, since
						# we may have unaccounted trailers that will sneak into the checksum.
						# The better way to handle this is to put trailers in their own
						# StructFu field, but I'm not a-gonna right now. :/
						ip_recalc(:ip_sum) if respond_to? :ip_header
						recalc(:tcp) if respond_to? :tcp_header
						recalc(:udp) if respond_to? :udp_header
					end
				else # You're not big enough for Ethernet. 
					@invalid_header.read(io)
				end	
				# @headers[0]
				self
			rescue ::Exception => e
				# remove last header
				# nested_types = self.headers.collect {|header| header.class}
				# nested_types.pop # whatever this packet type is, we weren't able to parse it
				self.headers.pop
				return_header_type = self.headers[self.headers.length-1].class.to_s
				retklass = PacketFu::InvalidPacket
				seekpos = 0
				target_header = @invalid_header
				case return_header_type.to_s
				when "PacketFu::EthHeader"
					retklass = PacketFu::EthPacket
					seekpos = 0x0e
					target_header = @eth_header
				when "PacketFu::IPHeader"
					retklass = PacketFu::IPPacket
					seekpos = 0x0e + @ip_header.ip_hl * 4
					target_header = @ip_header
				when "PacketFu::TCPHeader"
					retklass = PacketFu::TCPPacket
					seekpos = 0x0e + @ip_header.ip_hl * 4 + @tcpheader.tcp_hlen
					target_header = @tcp_header
				when "PacketFu::UDPHeader"
					retklass = PacketFu::UDPPacket
				when "PacketFu::ARPHeader"
					retklass = PacketFu::ARPPacket
				when "PacketFu::ICMPHeader"
					retklass = PacketFu::ICMPPacket
				when "PacketFu::IPv6Header"
					retklass = PacketFu::IPv6Packet
				else
				end
			
				io = io[seekpos,io.length - seekpos]
				target_header.body = io
				p = retklass.new
				p.headers = self.headers
				p
				raise e if $debug
			end
		end

		# Peek provides summary data on packet contents.
		# Each packet type should provide its own peek method, and shouldn't exceed 80 characters wide (for
		# easy reading in normal irb shells). If they don't, this default summary will step in.
		def peek(args={})
			peek_data = ["? "]
			peek_data << "%-5d" % self.to_s.size
			peek_data << "%68s" % self.to_s[0,34].unpack("H*")[0]
			peek_data.join
		end

		# Hexify provides a neatly-formatted dump of binary data, familar to hex readers.
		def hexify(str)
			if str.respond_to? :force_encoding
				str.force_encoding("ASCII-8BIT")
			end
			hexascii_lines = str.to_s.unpack("H*")[0].scan(/.{1,32}/)
			chars = str.to_s.gsub(/[\x00-\x1f\x7f-\xff]/,'.')
			chars_lines = chars.scan(/.{1,16}/)
			ret = []
			hexascii_lines.size.times {|i| ret << "%-48s  %s" % [hexascii_lines[i].gsub(/(.{2})/,"\\1 "),chars_lines[i]]}
			ret.join("\n")
		end

		# Returns a hex-formatted representation of the packet.
		#
		# ==== Arguments
		#
		# 0..9 : If a number is given only the layer in @header[arg] will be displayed. Note that this will include all @headers included in that header.
		# :layers : If :layers is specified, the dump will return an array of headers by layer level.
		# :all : An alias for arg=0.
		#
		# ==== Examples
		#
		#   irb(main):003:0> pkt = TCPPacket.new
		#   irb(main):003:0> puts pkt.inspect_hex(:layers)
		#   00 1a c5 00 00 00 00 1a c5 00 00 00 08 00 45 00   ..............E.
		#   00 28 83 ce 00 00 ff 06 38 02 00 00 00 00 00 00   .(......8.......
		#   00 00 a6 0f 00 00 ac 89 7b 26 00 00 00 00 50 00   ........{&....P.
		#   40 00 a2 25 00 00                                 @..%..
		#   45 00 00 28 83 ce 00 00 ff 06 38 02 00 00 00 00   E..(......8.....
		#   00 00 00 00 a6 0f 00 00 ac 89 7b 26 00 00 00 00   ..........{&....
		#   50 00 40 00 a2 25 00 00                           P.@..%..
		#   a6 0f 00 00 ac 89 7b 26 00 00 00 00 50 00 40 00   ......{&....P.@.
		#   a2 25 00 00                                       .%..
		#   => nil
		#   irb(main):004:0> puts pkt.inspect_hex(:layers)[2]
		#   a6 0f 00 00 ac 89 7b 26 00 00 00 00 50 00 40 00   ......{&....P.@.
		#   a2 25 00 00                                       .%..
		#   => nil
		#
		# TODO: Colorize this! Everyone loves colorized irb output.
		def inspect_hex(arg=0)
			case arg
			when :layers
				ret = []
				@headers.size.times do |i|
					ret << hexify(@headers[i])
				end
				ret
			when (0..9)
				if @headers[arg]
					hexify(@headers[arg])
				else
					nil
				end
			when :all
				inspect_hex(0)
			end
		end

		# For packets, inspect is overloaded as inspect_hex(0).
		# Not sure if this is a great idea yet, but it sure makes
		# the irb output more sane.
		#
		# If you hate this, you can run PacketFu.toggle_inspect to return
		# to the typical (and often unreadable) Object#inspect format.
		def inspect
			self.proto.join("|") + "\n" + self.inspect_hex
		end

		# Returns the size of the packet (as a binary string)
		def size
			self.to_s.size
		end

		# Returns an array of protocols contained in this packet. For example:
		#
		#   t = PacketFu::TCPPacket.new
		#   => 00 1a c5 00 00 00 00 1a c5 00 00 00 08 00 45 00   ..............E.
		#   00 28 3c ab 00 00 ff 06 7f 25 00 00 00 00 00 00   .(<......%......
		#   00 00 93 5e 00 00 ad 4f e4 a4 00 00 00 00 50 00   ...^...O......P.
		#   40 00 4a 92 00 00                                 @.J...
		#   t.proto
		#   => ["Eth", "IP", "TCP"]
		#
		def proto
			type_array = []
			self.headers.each {|header| type_array << header.class.to_s.split('::').last.gsub(/Header$/,'')}
			type_array
		end

		alias_method :protocol, :proto

		# Returns true if this is an Invalid packet. Else, false.
		def is_invalid? ;	self.proto.include? "Invalid"; end
		# Returns true if this is an Ethernet packet. Else, false.
		def is_ethernet? ;	self.proto.include? "Eth"; end
		alias_method :is_eth?, :is_ethernet?
		# Returns true if this is an IP packet. Else, false.
		def is_ip? ;	self.proto.include? "IP"; end
		# Returns true if this is an TCP packet. Else, false.
		def is_tcp? ;	self.proto.include? "TCP"; end
		# Returns true if this is an UDP packet. Else, false.
		def is_udp? ;	self.proto.include? "UDP"; end
		# Returns true if this is an HSRP packet. Else, false.
		def is_hsrp? ;	self.proto.include? "HSRP"; end
		# Returns true if this is an ARP packet. Else, false.
		def is_arp? ; self.proto.include? "ARP"; end
		# Returns true if this is an IPv6 packet. Else, false.
		def is_ipv6? ; self.proto.include? "IPv6" ; end
		# Returns true if this is an ICMP packet. Else, false.
		def is_icmp? ; self.proto.include? "ICMP" ; end
		# Returns true if this is an IPv6 packet. Else, false.
		def is_ipv6? ; self.proto.include? "IPv6" ; end
		# Returns true if the outermost layer has data. Else, false.
		def has_data? ; self.payload.size.zero? ? false : true ; end

		alias_method :length, :size

		def initialize(args={})
			if args[:config]
				args[:config].each_pair do |k,v|
					case k
					when :eth_daddr; @eth_header.eth_daddr=v if @eth_header
					when :eth_saddr; @eth_header.eth_saddr=v if @eth_header
					when :ip_saddr; @ip_header.ip_saddr=v		 if @ip_header
					when :iface; @iface = v
					end
				end
			end
		end

	end # class Packet

	@@inspect_style = :pretty

	# If @@inspect_style is :ugly, set the inspect method to the usual inspect. 
	# By default, @@inspect_style is :pretty. This default may change if people
	# hate it.
	# Since PacketFu is designed with irb in mind, the normal inspect is way too
	# verbose when new packets are created, and it ruins the aesthetics of the
	# PacketFu console or quick hping-like exercises in irb.
	#
	# However, there are cases where knowing things like object id numbers, the complete
	# @header array, etc. is useful (especially in debugging). So, toggle_inspect
	# provides a means for a script to declar which style of inspect to use.
	# 
	# This method may be an even worse idea than the original monkeypatch to Packet.inspect,
	# since it would almost certainly be better to redefine inspect just in the PacketFu console.
	# We'll see what happens.
	#
	# == Example
	#
	#  irb(main):001:0> p = PacketFu::TCPPacket.new
	#  => Eth|IP|TCP
	#  00 1a c5 00 00 00 00 1a c5 00 00 00 08 00 45 00   ..............E.
	#  00 28 ea d7 00 00 ff 06 d0 f8 00 00 00 00 00 00   .(..............
	#  00 00 a9 76 00 00 f9 28 7e 95 00 00 00 00 50 00   ...v...(~.....P.
	#  40 00 4e b0 00 00                                 @.N...
	#  irb(main):002:0> PacketFu.toggle_inspect
	#  => :ugly
	#  irb(main):003:0> p = PacketFu::TCPPacket.new
	#  => #<PacketFu::TCPPacket:0xb7aaf96c @ip_header=#<struct PacketFu::IPHeader ip_v=4, ip_hl=5, ip_tos=#<struct StructFu::Int8 value=nil, endian=nil, width=1, default=0>, ip_len=#<struct StructFu::Int16 value=20, endian=:big, width=2, default=0>, ip_id=#<struct StructFu::Int16 value=58458, endian=:big, width=2, default=0>, ip_frag=#<struct StructFu::Int16 value=nil, endian=:big, width=2, default=0>, ip_ttl=#<struct StructFu::Int8 value=32, endian=nil, width=1, default=0>, ip_proto=#<struct StructFu::Int8 value=6, endian=nil, width=1, default=0>, ip_sum=#<struct StructFu::Int16 value=65535, endian=:big, width=2, default=0>, ip_src=#<struct PacketFu::Octets o1=#<struct StructFu::Int8 value=0, endian=nil, width=1, default=0>, o2=#<struct StructFu::Int8 value=0, endian=nil, width=1, default=0>, o3=#<struct StructFu::Int8 value=0, endian=nil, width=1, default=0>, o4=#<struct StructFu::Int8 value=0, endian=nil, width=1, default=0>>, ip_dst=#<struct PacketFu::Octets o1=#<struct StructFu::Int8 value=0, endian=nil, width=1, default=0>, o2=#<struct StructFu::Int8 value=0, endian=nil, width=1, default=0>, o3=#<struct StructFu::Int8 value=0, endian=nil, width=1, default=0>, o4=#<struct StructFu::Int8 value=0, endian=nil, width=1, default=0>>, body=#<struct PacketFu::TCPHeader tcp_src=#<struct StructFu::Int16 value=17222, endian=:big, width=2, default=0>, tcp_dst=#<struct StructFu::Int16 value=nil, endian=:big, width=2, default=0>, tcp_seq=#<struct StructFu::Int32 value=1528113240, endian=:big, width=4, default=0>, tcp_ack=#<struct StructFu::Int32 value=nil, endian=:big, width=4, default=0>, tcp_hlen=#<struct PacketFu::TcpHlen hlen=5>, tcp_reserved=#<struct PacketFu::TcpReserved r1=0, r2=0, r3=0>, tcp_ecn=#<struct PacketFu::TcpEcn n=nil, c=nil, e=nil>, tcp_flags=#<struct PacketFu::TcpFlags urg=0, ack=0, psh=0, rst=0, syn=0, fin=0>, tcp_win=#<struct StructFu::Int16 value=16384, endian=:big, width=2, default=0>, tcp_sum=#<struct StructFu::Int16 value=43333, endian=:big, width=2, default=0>, tcp_urg=#<struct StructFu::Int16 value=nil, endian=:big, width=2, default=0>, tcp_opts=[], body="">>, @tcp_header=#<struct PacketFu::TCPHeader tcp_src=#<struct StructFu::Int16 value=17222, endian=:big, width=2, default=0>, tcp_dst=#<struct StructFu::Int16 value=nil, endian=:big, width=2, default=0>, tcp_seq=#<struct StructFu::Int32 value=1528113240, endian=:big, width=4, default=0>, tcp_ack=#<struct StructFu::Int32 value=nil, endian=:big, width=4, default=0>, tcp_hlen=#<struct PacketFu::TcpHlen hlen=5>, tcp_reserved=#<struct PacketFu::TcpReserved r1=0, r2=0, r3=0>, tcp_ecn=#<struct PacketFu::TcpEcn n=nil, c=nil, e=nil>, tcp_flags=#<struct PacketFu::TcpFlags urg=0, ack=0, psh=0, rst=0, syn=0, fin=0>, tcp_win=#<struct StructFu::Int16 value=16384, endian=:big, width=2, default=0>, tcp_sum=#<struct StructFu::Int16 value=43333, endian=:big, width=2, default=0>, tcp_urg=#<struct StructFu::Int16 value=nil, endian=:big, width=2, default=0>, tcp_opts=[], body="">, @eth_header=#<struct PacketFu::EthHeader eth_dst=#<struct PacketFu::EthMac oui=#<struct PacketFu::EthOui b0=nil, b1=nil, b2=nil, b3=nil, b4=nil, b5=nil, local=0, multicast=nil, oui=428>, nic=#<struct PacketFu::EthNic n0=nil, n1=nil, n2=nil>>, eth_src=#<struct PacketFu::EthMac oui=#<struct PacketFu::EthOui b0=nil, b1=nil, b2=nil, b3=nil, b4=nil, b5=nil, local=0, multicast=nil, oui=428>, nic=#<struct PacketFu::EthNic n0=nil, n1=nil, n2=nil>>, eth_proto=#<struct StructFu::Int16 value=2048, endian=:big, width=2, default=0>, body=#<struct PacketFu::IPHeader ip_v=4, ip_hl=5, ip_tos=#<struct StructFu::Int8 value=nil, endian=nil, width=1, default=0>, ip_len=#<struct StructFu::Int16 value=20, endian=:big, width=2, default=0>, ip_id=#<struct StructFu::Int16 value=58458, endian=:big, width=2, default=0>, ip_frag=#<struct StructFu::Int16 value=nil, endian=:big, width=2, default=0>, ip_ttl=#<struct StructFu::Int8 value=32, endian=nil, width=1, default=0>, ip_proto=#<struct StructFu::Int8 value=6, endian=nil, width=1, default=0>, ip_sum=#<struct StructFu::Int16 value=65535, endian=:big, width=2, default=0>, ip_src=#<struct PacketFu::Octets o1=#<struct StructFu::Int8 value=0, endian=nil, width=1, default=0>, o2=#<struct StructFu::Int8 value=0, endian=nil, width=1, default=0>, o3=#<struct StructFu::Int8 value=0, endian=nil, width=1, default=0>, o4=#<struct StructFu::Int8 value=0, endian=nil, width=1, default=0>>, ip_dst=#<struct PacketFu::Octets o1=#<struct StructFu::Int8 value=0, endian=nil, width=1, default=0>, o2=#<struct StructFu::Int8 value=0, endian=nil, width=1, default=0>, o3=#<struct StructFu::Int8 value=0, endian=nil, width=1, default=0>, o4=#<struct StructFu::Int8 value=0, endian=nil, width=1, default=0>>, body=#<struct PacketFu::TCPHeader tcp_src=#<struct StructFu::Int16 value=17222, endian=:big, width=2, default=0>, tcp_dst=#<struct StructFu::Int16 value=nil, endian=:big, width=2, default=0>, tcp_seq=#<struct StructFu::Int32 value=1528113240, endian=:big, width=4, default=0>, tcp_ack=#<struct StructFu::Int32 value=nil, endian=:big, width=4, default=0>, tcp_hlen=#<struct PacketFu::TcpHlen hlen=5>, tcp_reserved=#<struct PacketFu::TcpReserved r1=0, r2=0, r3=0>, tcp_ecn=#<struct PacketFu::TcpEcn n=nil, c=nil, e=nil>, tcp_flags=#<struct PacketFu::TcpFlags urg=0, ack=0, psh=0, rst=0, syn=0, fin=0>, tcp_win=#<struct StructFu::Int16 value=16384, endian=:big, width=2, default=0>, tcp_sum=#<struct StructFu::Int16 value=43333, endian=:big, width=2, default=0>, tcp_urg=#<struct StructFu::Int16 value=nil, endian=:big, width=2, default=0>, tcp_opts=[], body="">>>, @headers=[#<struct PacketFu::EthHeader eth_dst=#<struct PacketFu::EthMac oui=#<struct PacketFu::EthOui b0=nil, b1=nil, b2=nil, b3=nil, b4=nil, b5=nil, local=0, multicast=nil, oui=428>, nic=#<struct PacketFu::EthNic n0=nil, n1=nil, n2=nil>>, eth_src=#<struct PacketFu::EthMac oui=#<struct PacketFu::EthOui b0=nil, b1=nil, b2=nil, b3=nil, b4=nil, b5=nil, local=0, multicast=nil, oui=428>, nic=#<struct PacketFu::EthNic n0=nil, n1=nil, n2=nil>>, eth_proto=#<struct StructFu::Int16 value=2048, endian=:big, width=2, default=0>, body=#<struct PacketFu::IPHeader ip_v=4, ip_hl=5, ip_tos=#<struct StructFu::Int8 value=nil, endian=nil, width=1, default=0>, ip_len=#<struct StructFu::Int16 value=20, endian=:big, width=2, default=0>, ip_id=#<struct StructFu::Int16 value=58458, endian=:big, width=2, default=0>, ip_frag=#<struct StructFu::Int16 value=nil, endian=:big, width=2, default=0>, ip_ttl=#<struct StructFu::Int8 value=32, endian=nil, width=1, default=0>, ip_proto=#<struct StructFu::Int8 value=6, endian=nil, width=1, default=0>, ip_sum=#<struct StructFu::Int16 value=65535, endian=:big, width=2, default=0>, ip_src=#<struct PacketFu::Octets o1=#<struct StructFu::Int8 value=0, endian=nil, width=1, default=0>, o2=#<struct StructFu::Int8 value=0, endian=nil, width=1, default=0>, o3=#<struct StructFu::Int8 value=0, endian=nil, width=1, default=0>, o4=#<struct StructFu::Int8 value=0, endian=nil, width=1, default=0>>, ip_dst=#<struct PacketFu::Octets o1=#<struct StructFu::Int8 value=0, endian=nil, width=1, default=0>, o2=#<struct StructFu::Int8 value=0, endian=nil, width=1, default=0>, o3=#<struct StructFu::Int8 value=0, endian=nil, width=1, default=0>, o4=#<struct StructFu::Int8 value=0, endian=nil, width=1, default=0>>, body=#<struct PacketFu::TCPHeader tcp_src=#<struct StructFu::Int16 value=17222, endian=:big, width=2, default=0>, tcp_dst=#<struct StructFu::Int16 value=nil, endian=:big, width=2, default=0>, tcp_seq=#<struct StructFu::Int32 value=1528113240, endian=:big, width=4, default=0>, tcp_ack=#<struct StructFu::Int32 value=nil, endian=:big, width=4, default=0>, tcp_hlen=#<struct PacketFu::TcpHlen hlen=5>, tcp_reserved=#<struct PacketFu::TcpReserved r1=0, r2=0, r3=0>, tcp_ecn=#<struct PacketFu::TcpEcn n=nil, c=nil, e=nil>, tcp_flags=#<struct PacketFu::TcpFlags urg=0, ack=0, psh=0, rst=0, syn=0, fin=0>, tcp_win=#<struct StructFu::Int16 value=16384, endian=:big, width=2, default=0>, tcp_sum=#<struct StructFu::Int16 value=43333, endian=:big, width=2, default=0>, tcp_urg=#<struct StructFu::Int16 value=nil, endian=:big, width=2, default=0>, tcp_opts=[], body="">>>, #<struct PacketFu::IPHeader ip_v=4, ip_hl=5, ip_tos=#<struct StructFu::Int8 value=nil, endian=nil, width=1, default=0>, ip_len=#<struct StructFu::Int16 value=20, endian=:big, width=2, default=0>, ip_id=#<struct StructFu::Int16 value=58458, endian=:big, width=2, default=0>, ip_frag=#<struct StructFu::Int16 value=nil, endian=:big, width=2, default=0>, ip_ttl=#<struct StructFu::Int8 value=32, endian=nil, width=1, default=0>, ip_proto=#<struct StructFu::Int8 value=6, endian=nil, width=1, default=0>, ip_sum=#<struct StructFu::Int16 value=65535, endian=:big, width=2, default=0>, ip_src=#<struct PacketFu::Octets o1=#<struct StructFu::Int8 value=0, endian=nil, width=1, default=0>, o2=#<struct StructFu::Int8 value=0, endian=nil, width=1, default=0>, o3=#<struct StructFu::Int8 value=0, endian=nil, width=1, default=0>, o4=#<struct StructFu::Int8 value=0, endian=nil, width=1, default=0>>, ip_dst=#<struct PacketFu::Octets o1=#<struct StructFu::Int8 value=0, endian=nil, width=1, default=0>, o2=#<struct StructFu::Int8 value=0, endian=nil, width=1, default=0>, o3=#<struct StructFu::Int8 value=0, endian=nil, width=1, default=0>, o4=#<struct StructFu::Int8 value=0, endian=nil, width=1, default=0>>, body=#<struct PacketFu::TCPHeader tcp_src=#<struct StructFu::Int16 value=17222, endian=:big, width=2, default=0>, tcp_dst=#<struct StructFu::Int16 value=nil, endian=:big, width=2, default=0>, tcp_seq=#<struct StructFu::Int32 value=1528113240, endian=:big, width=4, default=0>, tcp_ack=#<struct StructFu::Int32 value=nil, endian=:big, width=4, default=0>, tcp_hlen=#<struct PacketFu::TcpHlen hlen=5>, tcp_reserved=#<struct PacketFu::TcpReserved r1=0, r2=0, r3=0>, tcp_ecn=#<struct PacketFu::TcpEcn n=nil, c=nil, e=nil>, tcp_flags=#<struct PacketFu::TcpFlags urg=0, ack=0, psh=0, rst=0, syn=0, fin=0>, tcp_win=#<struct StructFu::Int16 value=16384, endian=:big, width=2, default=0>, tcp_sum=#<struct StructFu::Int16 value=43333, endian=:big, width=2, default=0>, tcp_urg=#<struct StructFu::Int16 value=nil, endian=:big, width=2, default=0>, tcp_opts=[], body="">>, #<struct PacketFu::TCPHeader tcp_src=#<struct StructFu::Int16 value=17222, endian=:big, width=2, default=0>, tcp_dst=#<struct StructFu::Int16 value=nil, endian=:big, width=2, default=0>, tcp_seq=#<struct StructFu::Int32 value=1528113240, endian=:big, width=4, default=0>, tcp_ack=#<struct StructFu::Int32 value=nil, endian=:big, width=4, default=0>, tcp_hlen=#<struct PacketFu::TcpHlen hlen=5>, tcp_reserved=#<struct PacketFu::TcpReserved r1=0, r2=0, r3=0>, tcp_ecn=#<struct PacketFu::TcpEcn n=nil, c=nil, e=nil>, tcp_flags=#<struct PacketFu::TcpFlags urg=0, ack=0, psh=0, rst=0, syn=0, fin=0>, tcp_win=#<struct StructFu::Int16 value=16384, endian=:big, width=2, default=0>, tcp_sum=#<struct StructFu::Int16 value=43333, endian=:big, width=2, default=0>, tcp_urg=#<struct StructFu::Int16 value=nil, endian=:big, width=2, default=0>, tcp_opts=[], body="">]>
	#  irb(main):004:0> 
	def toggle_inspect
		if @@inspect_style == :pretty
			eval("class Packet; def inspect; super; end; end")
			@@inspect_style = :ugly
		else
			eval("class Packet; def inspect; self.proto.join('|') + \"\n\" + self.inspect_hex; end; end")
			@@inspect_style = :pretty
		end
	end

end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
