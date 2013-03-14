# -*- coding: binary -*-
module PacketFu

	# Packet is the parent class of EthPacket, IPPacket, UDPPacket, TCPPacket, and all
	# other packets. It acts as both a singleton class, so things like
	# Packet.parse can happen, and as an abstract class to provide 
	# subclasses some structure.
	class Packet

		attr_reader :flavor # Packet Headers are responsible for their own specific flavor methods.
		attr_accessor :headers # All packets have a header collection, useful for determining protocol trees.
		attr_accessor :iface # Default inferface to send packets to
		attr_accessor :inspect_style # Default is :dissect, can also be :hex or :default

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
			iface = (iface || self.iface || PacketFu::Config.new.config[:iface]).to_s
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

		# Packets are bundles of lots of objects, so copying them
		# is a little complicated -- a dup of a packet is actually
		# full of pass-by-reference stuff in the @headers, so 
		# if you change one, you're changing all this copies, too.
		#
		# Normally, this doesn't seem to be a big deal, and it's
		# a pretty decent performance tradeoff. But, if you're going
		# to be creating a template packet to base a bunch of slightly
		# different ones off of (like a fuzzer might), you'll want
		# to use clone()
		def clone
			Packet.parse(self.to_s)
		end

		# If two packets are represented as the same binary string, and
		# they're both actually PacketFu packets of the same sort, they're equal.
		#
		# The intuitive result is that a packet of a higher layer (like DNSPacket)
		# can be equal to a packet of a lower level (like UDPPacket) as long as
		# the bytes are equal (this can come up if a transport-layer packet has
		# a hand-crafted payload that is identical to what would have been created
		# by using an application layer packet)
		def ==(other)
			return false unless other.kind_of? self.class
			return false unless other.respond_to? :to_s
			self.to_s == other.to_s
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
		# === Format
		# 
		#   * A one or two character protocol initial. It should be unique
		#   * The packet size
		#   * Useful data in a human-usable form.
		#
		# Ideally, related peek_formats will all line up with each other
		# when printed to the screen.
		#
		# === Example
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
			str.force_encoding("ASCII-8BIT") if str.respond_to? :force_encoding
			hexascii_lines = str.to_s.unpack("H*")[0].scan(/.{1,32}/)
			regex = Regexp.new('[\x00-\x1f\x7f-\xff]', nil, 'n')
			chars = str.to_s.gsub(regex,'.')
			chars_lines = chars.scan(/.{1,16}/)
			ret = []
			hexascii_lines.size.times {|i| ret << "%-48s  %s" % [hexascii_lines[i].gsub(/(.{2})/,"\\1 "),chars_lines[i]]}
			ret.join("\n")
		end

		# If @inspect_style is :default (or :ugly), the inspect output is the usual
		# inspect. 
		#
		# If @inspect_style is :hex (or :pretty), the inspect output is
		# a much more compact hexdump-style, with a shortened set of packet header
		# names at the top.
		#
		# If @inspect_style is :dissect (or :verbose), the inspect output is the
		# longer, but more readable, dissection of the packet. This is the default.
		#
		# TODO: Have an option for colors. Everyone loves colorized irb output.
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

		def dissection_table
			table = []
			@headers.each_with_index do |header,table_idx|
				proto = header.class.name.sub(/^.*::/,"")
				table << [proto,[]]
				header.class.members.each do |elem|
					elem_sym = elem.to_sym # to_sym needed for 1.8
					next if elem_sym == :body 
					elem_type_value = []
					elem_type_value[0] = elem
					readable_element = "#{elem}_readable"
					if header.respond_to? readable_element
						elem_type_value[1] = header.send(readable_element)
					else
						elem_type_value[1] = header.send(elem)
					end
					elem_type_value[2] = header[elem.to_sym].class.name 
					table[table_idx][1] << elem_type_value
				end
			end
			table
			if @headers.last.members.map {|x| x.to_sym }.include? :body
				body_part = [:body, self.payload, @headers.last.body.class.name]
			end
			table << body_part
		end

		# Renders the dissection_table suitable for screen printing. Can take
		# one or two arguments. If just the one, only that layer will be displayed
		# take either a range or a number -- if a range, only protos within
		# that range will be rendered. If an integer, only that proto
		# will be rendered.
		def dissect
			dtable = self.dissection_table
			hex_body = nil
			if dtable.last.kind_of?(Array) and dtable.last.first == :body
				body = dtable.pop 
				hex_body = hexify(body[1])
			end
			elem_widths = [0,0,0]
			dtable.each do |proto_table|
				proto_table[1].each do |elems|
					elems.each_with_index do |e,i|
						width = e.size
						elem_widths[i] = width if width > elem_widths[i]
					end
				end
			end
			total_width = elem_widths.inject(0) {|sum,x| sum+x} 
			table = ""
			dtable.each do |proto|
				table << "--"
				table << proto[0] 
				if total_width > proto[0].size
					table << ("-" * (total_width - proto[0].size + 2))
				else
					table << ("-" * (total_width + 2))
				end
				table << "\n"
				proto[1].each do |elems|
					table << "  "
					elems_table = []
					(0..2).each do |i|
						elems_table << ("%-#{elem_widths[i]}s" % elems[i])
					end
					table << elems_table.join("\s")
					table << "\n"
				end
			end
			if hex_body && !hex_body.empty?
				table << "-" * 66
				table << "\n"
				table << "00-01-02-03-04-05-06-07-08-09-0a-0b-0c-0d-0e-0f---0123456789abcdef\n"
				table << "-" * 66
				table << "\n"
				table << hex_body
			end
			table
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
			case @inspect_style
			when :dissect
				self.dissect
			when :hex
				self.proto.join("|") + "\n" + self.inspect_hex
			else
				super
			end
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

		# the Packet class should not be instantiated directly, since it's an 
		# abstract class that real packet types inherit from. Sadly, this
		# makes the Packet class more difficult to test directly.
		def initialize(args={})
			if self.class.name =~ /(::|^)PacketFu::Packet$/
				raise NoMethodError, "method `new' called for abstract class #{self.class.name}"
			end
			@inspect_style = args[:inspect_style] || PacketFu.inspect_style || :dissect
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

		# Delegate to PacketFu's inspect_style, since the
		# class variable name is the same. Yay for namespace
		# pollution!
		def inspect_style=()
			PacketFu.inspect_style(arg)
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
end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
