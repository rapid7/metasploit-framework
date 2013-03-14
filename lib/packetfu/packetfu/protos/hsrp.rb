# -*- coding: binary -*-
module PacketFu

	# HSRPHeader is a complete HSRP struct, used in HSRPPacket. HSRP is typically used for
	# fault-tolerant default gateway in IP routing environment.
	#
	# For more on HSRP packets, see http://www.networksorcery.com/enp/protocol/hsrp.htm
	#
	# Submitted by fropert@packetfault.org. Thanks, Francois!
	#
	# ==== Header Definition
	#
	#   Int8    :hsrp_version      Default: 0     # Version
	#   Int8    :hsrp_opcode                      # Opcode
	#   Int8    :hsrp_state                       # State
	#   Int8    :hsrp_hellotime    Default: 3     # Hello Time
	#   Int8    :hsrp_holdtime     Default: 10    # Hold Time
	#   Int8    :hsrp_priority                    # Priority
	#   Int8    :hsrp_group                       # Group
	#   Int8    :hsrp_reserved     Default: 0     # Reserved
	#   String  :hsrp_password                    # Authentication Data
	#   Octets  :hsrp_vip                         # Virtual IP Address
	#   String  :body
	class HSRPHeader < Struct.new(:hsrp_version, :hsrp_opcode, :hsrp_state,
								  :hsrp_hellotime, :hsrp_holdtime,
								  :hsrp_priority, :hsrp_group,
								  :hsrp_reserved, :hsrp_password,
								  :hsrp_vip, :body)

		include StructFu

		def initialize(args={})
			super(
				Int8.new(args[:hsrp_version] || 0),
				Int8.new(args[:hsrp_opcode]),
				Int8.new(args[:hsrp_state]),
				Int8.new(args[:hsrp_hellotime] || 3),
				Int8.new(args[:hsrp_holdtime] || 10),
				Int8.new(args[:hsrp_priority]),
				Int8.new(args[:hsrp_group]),
				Int8.new(args[:hsrp_reserved] || 0),
				StructFu::String.new.read(args[:hsrp_password] || "cisco\x00\x00\x00"),
				Octets.new.read(args[:hsrp_vip] || ("\x00" * 4)),
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
			self[:hsrp_version].read(str[0,1])
			self[:hsrp_opcode].read(str[1,1])
			self[:hsrp_state].read(str[2,1])
			self[:hsrp_hellotime].read(str[3,1])
			self[:hsrp_holdtime].read(str[4,1])
			self[:hsrp_priority].read(str[5,1])
			self[:hsrp_group].read(str[6,1])
			self[:hsrp_reserved].read(str[7,1])
			self[:hsrp_password].read(str[8,8])
			self[:hsrp_vip].read(str[16,4])
			self[:body].read(str[20,str.size]) if str.size > 20
			self
		end

		# Setter for the type.
		def hsrp_version=(i); typecast i; end
		# Getter for the type.
		def hsrp_version; self[:hsrp_version].to_i; end
		# Setter for the type.
		def hsrp_opcode=(i); typecast i; end
		# Getter for the type.
		def hsrp_opcode; self[:hsrp_opcode].to_i; end
		# Setter for the type.
		def hsrp_state=(i); typecast i; end
		# Getter for the type.
		def hsrp_state; self[:hsrp_state].to_i; end
		# Setter for the type.
		def hsrp_hellotime=(i); typecast i; end
		# Getter for the type.
		def hsrp_hellotime; self[:hsrp_hellotime].to_i; end
		# Setter for the type.
		def hsrp_holdtime=(i); typecast i; end
		# Getter for the type.
		def hsrp_holdtime; self[:hsrp_holdtime].to_i; end
		# Setter for the type.
		def hsrp_priority=(i); typecast i; end
		# Getter for the type.
		def hsrp_priority; self[:hsrp_priority].to_i; end
		# Setter for the type.
		def hsrp_group=(i); typecast i; end
		# Getter for the type.
		def hsrp_group; self[:hsrp_group].to_i; end
		# Setter for the type.
		def hsrp_reserved=(i); typecast i; end
		# Getter for the type.
		def hsrp_reserved; self[:hsrp_reserved].to_i; end

		def hsrp_addr=(addr)
			self[:hsrp_vip].read_quad(addr)
		end

		# Returns a more readable IP source address.
		def hsrp_addr
			self[:hsrp_vip].to_x
		end

		# Readability aliases

		alias :hsrp_vip_readable :hsrp_addr

		def hsrp_password_readable
			hsrp_password.to_s.inspect
		end

	end

	# HSRPPacket is used to construct HSRP Packets. They contain an EthHeader, an IPHeader, and a UDPHeader.
	#
	# == Example
	#
	#  hsrp_pkt.new
	#  hsrp_pkt.hsrp_opcode = 0
	#  hsrp_pkt.hsrp_state = 16
	#  hsrp_pkt.hsrp_priority = 254
	#  hsrp_pkt.hsrp_group = 1
	#  hsrp_pkt.hsrp_vip = 10.100.100.254
	#  hsrp_pkt.recalc
	#  hsrp_pkt.to_f('/tmp/hsrp.pcap')
	#
	# == Parameters
	#
	#  :eth
	#   A pre-generated EthHeader object.
	#  :ip
	#   A pre-generated IPHeader object.
	#  :udp
	#   A pre-generated UDPHeader object.
	#  :flavor
	#   TODO: HSRP packets don't tend have any flavor.
	#  :config
	#   A hash of return address details, often the output of Utils.whoami?
	class HSRPPacket < Packet

		attr_accessor :eth_header, :ip_header, :udp_header, :hsrp_header

		def self.can_parse?(str)
			return false unless str.size >= 54
			return false unless EthPacket.can_parse? str
			return false unless IPPacket.can_parse? str
			return false unless UDPPacket.can_parse? str
			temp_packet = UDPPacket.new
			temp_packet.read(str)
			if temp_packet.ip_ttl == 1 and [temp_packet.udp_sport,temp_packet.udp_dport] == [1985,1985] 
				return true
			else 
				return false
			end
		end

		def read(str=nil, args={})
			raise "Cannot parse `#{str}'" unless self.class.can_parse?(str)
			@eth_header.read(str)
			@ip_header.read(str[14,str.size])
			@eth_header.body = @ip_header
			@udp_header.read(str[14+(@ip_header.ip_hlen),str.size])
			@ip_header.body = @udp_header
			@hsrp_header.read(str[14+(@ip_header.ip_hlen)+8,str.size])
			@udp_header.body = @hsrp_header
			super(args)
			self
		end

		def initialize(args={})
			@eth_header = EthHeader.new(args).read(args[:eth])
			@ip_header = IPHeader.new(args).read(args[:ip])
			@ip_header.ip_proto = 0x11
			@udp_header = UDPHeader.new(args).read(args[:udp])
			@hsrp_header = HSRPHeader.new(args).read(args[:hsrp])
			@udp_header.body = @hsrp_header
			@ip_header.body = @udp_header
			@eth_header.body = @ip_header
			@headers = [@eth_header, @ip_header, @udp_header, @hsrp_header]
			super
		end

		# Peek provides summary data on packet contents.
		def peek_format
			peek_data = ["UH "]
			peek_data << "%-5d" % self.to_s.size
			peek_data << "%-16s" % self.hsrp_addr
			peek_data << "%-4d" % self.hsrp_group
			peek_data << "%-35s" % self.hsrp_password_readable
			peek_data << "%-15s" % self.ip_saddr
			peek_data.join
		end

	end

end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
