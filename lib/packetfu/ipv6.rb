
module PacketFu

	# AddrIpv6 handles addressing for IPv6Header
	#
	# ==== Header Definition
	#
	#
	# uint32be :a1
	# uint32be :a2
	# uint32be :a3
	# uint32be :a4
 class AddrIpv6 < BinData::MultiValue

		uint32be	:a1
		uint32be	:a2
		uint32be	:a3
		uint32be	:a4

	end

	# IPv6Header is complete IPv6 struct, used in IPv6Packet. 
	#
	# ==== Header Definition
	#
	#  bit4      :ipv6_v,    :initial_value => 6                        # Versiom
	#  bit8      :ipv6_class                                            # Class
	#  bit20     :ipv6_label                                            # Label
	#  uint16be  :ipv6_len,  :initial_value => lambda { ipv6_calc_len } # Payload length
	#  uint8     :ipv6_next                                             # Next Header
	#  uint8     :ipv6_hop,  :initial_value => 0xff                     # Hop limit
	#  addr_ipv6 :ipv6_src
	#  addr_ipv6 :ipv6_dst
	#  rest      :body
	class IPv6Header < BinData::MultiValue

		bit4			:ipv6_v,		:initial_value => 6			# Versiom
		bit8			:ipv6_class													# Class
		bit20			:ipv6_label													# Label
		uint16be	:ipv6_len,	:initial_value => lambda { ipv6_calc_len } # Payload length
		uint8			:ipv6_next													# Next Header
		uint8			:ipv6_hop,	:initial_value => 0xff	# Hop limit
		addr_ipv6	:ipv6_src
		addr_ipv6	:ipv6_dst
		rest			:body

		def ipv6_calc_len
			ipv6_len = self.body.size
		end

		def ipv6_recalc(arg=:all)
			case arg
			when :ipv6_len
				ipv6_calc_len
			when :all
				ipv6_recalc(:len)
			end
		end

		# Presents in a more readable form.
		def ipv6_saddr
			addr = [self.ipv6_src.a1,self.ipv6_src.a2,self.ipv6_src.a3,self.ipv6_src.a4].pack("NNNN")
			addr.unpack("H*")[0].scan(/.{8}/).collect {|x| x.sub(/^0*([0-9a-f])/,"\\1")}.join(":")
		end

		# Takes in a more readable form. Leading zero compression is fine, but that's it. :(
		def ipv6_saddr=(str)
			arr = str.split(':').collect {|x| x.to_i(16)}
			self.ipv6_src.a1 = arr[0]
			self.ipv6_src.a2 = arr[1]
			self.ipv6_src.a3 = arr[2]
			self.ipv6_src.a4 = arr[3]
		end

		# Presents in a more readable form.
		def ipv6_daddr
			addr = [self.ipv6_dst.a1,self.ipv6_dst.a2,self.ipv6_dst.a3,self.ipv6_dst.a4].pack("NNNN")
			addr.unpack("H*")[0].scan(/.{8}/).collect {|x| x.sub(/^0*([0-9a-f])/,"\\1")}.join(":")
		end

		# Takes in a more readable form. Leading zero compression is fine, but that's it. :(
		def ipv6_daddr=(str)
			arr = str.split(':').collect {|x| x.to_i(16)}
			self.ipv6_dst.a1 = arr[0]
			self.ipv6_dst.a2 = arr[1]
			self.ipv6_dst.a3 = arr[2]
			self.ipv6_dst.a4 = arr[3]
		end

	end # class IPv6Header

	# IPv6Packet is used to construct IPv6 Packets. They contain an EthHeader and an IPv6Header, and in
	# the distant, unknowable future, will take interesting IPv6ish payloads.
	#
	# This mostly complete, but not very useful. It's intended primarily as an example protocol.
	#
	# == Parameters
	#
	#   :eth
	#     A pre-generated EthHeader object.
	#   :ip
	#     A pre-generated IPHeader object.
	#   :flavor
	#     TODO: Sets the "flavor" of the IPv6 packet. No idea what this will look like, haven't done much IPv6 fingerprinting.
	#   :config
	#     A hash of return address details, often the output of Utils.whoami?
	class IPv6Packet < Packet

		attr_accessor :eth_header, :ipv6_header

		def ethernet?; true; end
		def ipv6?;     true; end

		def initialize(args={})
			@eth_header = (args[:eth] || EthHeader.new)
			@ipv6_header = (args[:ipv6]	|| IPv6Header.new)
			@eth_header.eth_proto = 0x86dd
			@eth_header.body=@ipv6_header

			@headers = [@eth_header, @arp_header]
			super
		end

		# Peek provides summary data on packet contents.
		def peek(args={})
			peek_data = ["6 "]
			peek_data << "%-5d" % self.to_s.size
			peek_data << self.ipv6_saddr
			peek_data << "->"
			peek_data << self.ipv6_daddr
			peek_data << " N:"
			peek_data << self.ipv6_next.to_s(16)
			peek_data.join
		end

	end # class IPv6Packet
	
end # module PacketFu