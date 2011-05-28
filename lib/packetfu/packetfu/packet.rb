module PacketFu

	# Packet is the parent class of EthPacket, IPPacket, UDPPacket, TCPPacket, and all
	# other packets. It acts as both a singleton class, so things like
	# Packet.parse can happen, and as an abstract class to provide 
	# subclasses some structure.
	class Packet

		attr_reader :flavor # Packet Headers are responsible for their own specific flavor methods.
		attr_accessor :headers # All packets have a header collection, useful for determining protocol trees.
		attr_accessor :iface # Default inferface to send packets to

		# Register subclasses in PacketFu.packet_class to do all kinds of neat things
		# that obviates those long if/else trees for parsing. It's pretty sweet.
		def self.inherited(subclass)
			PacketFu.add_packet_class(subclass)
		end

		# Force strings into binary.
		def self.force_binary(str)
			str.force_encoding "binary" if str.respond_to? :force_encoding
		end

		# Parse() creates the correct packet type based on the data, and returns the apporpiate
		# Packet subclass object. 
		#
		# There is an assumption here that all incoming packets are either EthPacket
		# or InvalidPacket types. This will be addressed pretty soon.
		#
		# If application-layer parsing is /not/ desired, that should be indicated explicitly
		# with an argument of  :parse_app => false. Otherwise, app-layer parsing will happen.
		#
		# It is no longer neccisary to manually add packet types here.
		def self.parse(packet=nil,args={})
			parse_app = true if(args[:parse_app].nil? or args[:parse_app])
			force_binary(packet)
			if parse_app
				classes = PacketFu.packet_classes.select {|pclass| pclass.can_parse? packet}
			else
				classes = PacketFu.packet_classes.select {|pclass| pclass.can_parse? packet}.reject {|pclass| pclass.layer_symbol == :application}
			end
			p = classes.sort {|x,y| x.layer <=> y.layer}.last.new
			parsed_packet = p.read(packet,args)
		end

		def handle_is_identity(ptype)
			idx = PacketFu.packet_prefixes.index(ptype.to_s.downcase)
			if idx
				self.kind_of? PacketFu.packet_classes[idx]
			else
				raise NoMethodError, "Undefined method `is_#{ptype}?' for #{self.class}."
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
		# this is a horrid hack. Stripping is useful (and fun!), but the default behavior really
		# should be to create payloads correctly, and /not/ treat extra FCS data as a payload.
		#
		# Finally, packet subclasses should take two arguments: the string that is the data
		# to be transmuted into a packet, as well as args. This superclass method is merely
		# concerned with handling args common to many packet formats (namely, fixing packets
		# on the fly)
		def read(args={})
			if args[:fix] || args[:recalc]
				ip_recalc(:ip_sum) if self.is_ip?
				recalc(:tcp) if self.is_tcp?
				recalc(:udp) if self.is_udp?
			end
		end

		# Peek provides summary data on packet contents.
		#
		# Each packet type should provide a peek_format.
		def peek(args={})
			idx = @headers.reverse.map {|h| h.respond_to? peek_format}.index(true)
			if idx
				@headers.reverse[idx].peek_format
			else
				peek_format
			end
		end

		# The peek_format is used to display a single line
		# of packet data useful for eyeballing. It should not exceed
		# 80 characters. The Packet superclass defines an example
		# peek_format, but it should hardly ever be triggered, since
		# peek traverses the @header list in reverse to find a suitable
		# format.
		#
		# == Format
		# 
		#   * A one or two character protocol initial. It should be unique
		#   * The packet size
		#   * Useful data in a human-usable form.
		#
		# Ideally, related peek_formats will all line up with each other
		# when printed to the screen.
		#
		# == Example
		#
		#    tcp_packet.peek
		#    #=> "T  1054 10.10.10.105:55000   ->   192.168.145.105:80 [......] S:adc7155b|I:8dd0"
		#    tcp_packet.peek.size
		#    #=> 79
		#   
		def peek_format
			peek_data = ["?  "]
			peek_data << "%-5d" % self.to_s.size
			peek_data << "%68s" % self.to_s[0,34].unpack("H*")[0]
			peek_data.join
		end

		# Defines the layer this packet type lives at, based on the number of headers it 
		# requires. Note that this has little to do with the OSI model, since TCP/IP
		# doesn't really have Session and Presentation layers. 
		#
		# Ethernet and the like are layer 1, IP, IPv6, and ARP are layer 2,
		# TCP, UDP, and other transport protocols are layer 3, and application
		# protocols are at layer 4 or higher. InvalidPackets have an arbitrary
		# layer 0 to distinguish them.
		#
		# Because these don't change much, it's cheaper just to case through them,
		# and only resort to counting headers if we don't have a match -- this
		# makes adding protocols somewhat easier, but of course you can just
		# override this method over there, too. This is merely optimized
		# for the most likely protocols you see on the Internet.
		def self.layer
			case self.name # Lol ran into case's fancy treatment of classes
			when /InvalidPacket$/; 0
			when /EthPacket$/; 1
			when /IPPacket$/, /ARPPacket$/, /IPv6Packet$/; 2
			when /TCPPacket$/, /UDPPacket$/, /ICMPPacket$/; 3
			when /HSRPPacket$/; 4
			else; self.new.headers.size
			end
		end

		def layer
			self.class.layer
		end

		def self.layer_symbol
			case self.layer
			when 0; :invalid
			when 1; :link
			when 2; :internet
			when 3; :transport
			else; :application
			end
		end

		def layer_symbol
			self.class.layer_symbol
		end

		# Packet subclasses must override this, since the Packet superclass
		# can't actually parse anything.
		def self.can_parse?(str)
			false
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

		alias :orig_kind_of? :kind_of?

		def kind_of?(klass)
			return true if orig_kind_of? klass
			packet_types = proto.map {|p| PacketFu.const_get("#{p}Packet")}
			match = false
			packet_types.each do |p|
				if p.ancestors.include? klass
					match =  true
					break
				end
			end
			return match
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

		#method_missing() delegates protocol-specific field actions to the apporpraite
		#class variable (which contains the associated packet type)
		#This register-of-protocols style switch will work for the 
		#forseeable future (there aren't /that/ many packet types), and it's a handy
		#way to know at a glance what packet types are supported.
		def method_missing(sym, *args, &block)
			case sym.to_s
			when /^is_([a-zA-Z0-9]+)\?/
				ptype = $1
				if PacketFu.packet_prefixes.index(ptype)
					self.send(:handle_is_identity, $1)
				else
					super
				end
			when /^([a-zA-Z0-9]+)_.+/
				ptype = $1
				if PacketFu.packet_prefixes.index(ptype)
					self.instance_variable_get("@#{ptype}_header").send(sym,*args, &block)
				else
					super
				end
			else
				super
			end
		end

		def respond_to?(sym, include_private = false)
			if sym.to_s =~ /^(invalid|eth|arp|ip|icmp|udp|hsrp|tcp|ipv6)_/
				self.instance_variable_get("@#{$1}_header").respond_to? sym
			elsif sym.to_s =~ /^is_([a-zA-Z0-9]+)\?/
				if PacketFu.packet_prefixes.index($1)
					true
				else
					super
				end
			else
				super
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
