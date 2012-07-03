# -*- coding: binary -*-
module PacketFu

	# Implements the Explict Congestion Notification for TCPHeader.
	#
	# ==== Header Definition
	#
	#
	#  Fixnum (1 bit)  :n
	#  Fixnum (1 bit)  :c
	#  Fixnum (1 bit)  :e
	class TcpEcn < Struct.new(:n, :c, :e)

		include StructFu

		def initialize(args={})
			super(args[:n], args[:c], args[:e]) if args
		end

		# Returns the TcpEcn field as an integer... even though it's going
		# to be split across a byte boundary.
		def to_i
			(n.to_i << 2) + (c.to_i << 1) + e.to_i
		end

		# Reads a string to populate the object.
		def read(str)
			force_binary(str)
			return self if str.nil? || str.size < 2
			if 1.respond_to? :ord
				byte1 = str[0].ord
				byte2 = str[1].ord
			else
				byte1 = str[0]
				byte2 = str[1]
			end
			self[:n] = byte1 & 0b00000001 == 0b00000001 ? 1 : 0
			self[:c] = byte2 & 0b10000000 == 0b10000000 ? 1 : 0
			self[:e] = byte2 & 0b01000000 == 0b01000000 ? 1 : 0
			self
		end

	end

  # Implements the Header Length for TCPHeader.
	#
	# ==== Header Definition
	#
	#   Fixnum (4 bits)  :hlen
	class TcpHlen < Struct.new(:hlen)
		
		include StructFu

		def initialize(args={})
			super(args[:hlen])
		end

		# Returns the TcpHlen field as an integer. Note these will become the high
		# bits at the TCP header's offset, even though the lower 4 bits
		# will be further chopped up.
		def to_i
			hlen.to_i & 0b1111
		end

		# Reads a string to populate the object.
		def read(str)
			force_binary(str)
			return self if str.nil? || str.size.zero?
			if 1.respond_to? :ord
				self[:hlen] = (str[0].ord & 0b11110000) >> 4
			else
				self[:hlen] = (str[0] & 0b11110000) >> 4
			end
			self
		end

		# Returns the object in string form.
		def to_s
			[self.to_i].pack("C")
		end

	end

	# Implements the Reserved bits for TCPHeader.
	#
	# ==== Header Definition
	#
	#
	#  Fixnum (1 bit)  :r1
	#  Fixnum (1 bit)  :r2
	#  Fixnum (1 bit)  :r3
	class TcpReserved < Struct.new(:r1, :r2, :r3)

		include StructFu

		def initialize(args={})
			super(
				args[:r1] || 0,
				args[:r2] || 0,
				args[:r3] || 0) if args.kind_of? Hash
		end

		# Returns the Reserved field as an integer.
		def to_i
			(r1.to_i << 2) + (r2.to_i << 1) + r3.to_i
		end

		# Reads a string to populate the object.
		def read(str)
			force_binary(str)
			return self if str.nil? || str.size.zero?
			if 1.respond_to? :ord
				byte = str[0].ord
			else
				byte = str[0]
			end
			self[:r1] = byte & 0b00000100 == 0b00000100 ? 1 : 0
			self[:r2] = byte & 0b00000010 == 0b00000010 ? 1 : 0
			self[:r3] = byte & 0b00000001 == 0b00000001 ? 1 : 0
			self
		end

	end

	# Implements flags for TCPHeader.
	#
	# ==== Header Definition
	#
	#  Fixnum (1 bit)  :urg
	#  Fixnum (1 bit)  :ack
	#  Fixnum (1 bit)  :psh
	#  Fixnum (1 bit)  :rst
	#  Fixnum (1 bit)  :syn
	#  Fixnum (1 bit)  :fin
	#
	# Flags can typically be set by setting them either to 1 or 0, or to true or false.
	class TcpFlags < Struct.new(:urg, :ack, :psh, :rst, :syn, :fin)

		include StructFu

		def initialize(args={})
			# This technique attemts to ensure that flags are always 0 (off)
			# or 1 (on). Statements like nil and false shouldn't be lurking in here.
			if args.nil? || args.size.zero?
				super( 0, 0, 0, 0, 0, 0)
			else
				super(
					(args[:urg] ? 1 : 0), 
					(args[:ack] ? 1 : 0), 
					(args[:psh] ? 1 : 0), 
					(args[:rst] ? 1 : 0), 
					(args[:syn] ? 1 : 0), 
					(args[:fin] ? 1 : 0)
				)
			end
		end

		# Returns the TcpFlags as an integer.
		# Also not a great candidate for to_s due to the short bitspace.
		def to_i
			(urg.to_i << 5) + (ack.to_i << 4) + (psh.to_i << 3) + 
			(rst.to_i << 2) + (syn.to_i << 1) + fin.to_i
		end

		# Helper to determine if this flag is a 1 or a 0.
		def zero_or_one(i=0)
			if i == 0 || i == false || i == nil
				0
			else
				1
			end
		end

		# Setter for the Urgent flag.
		def urg=(i); self[:urg] = zero_or_one(i); end
		# Setter for the Acknowlege flag.
		def ack=(i); self[:ack] = zero_or_one(i); end
		# Setter for the Push flag.
		def psh=(i); self[:psh] = zero_or_one(i); end
		# Setter for the Reset flag.
		def rst=(i); self[:rst] = zero_or_one(i); end
		# Setter for the Synchronize flag.
		def syn=(i); self[:syn] = zero_or_one(i); end
		# Setter for the Finish flag.
		def fin=(i); self[:fin] = zero_or_one(i); end

		# Reads a string to populate the object.
		def read(str)
			force_binary(str)
			return self if str.nil?
			if 1.respond_to? :ord
				byte = str[0].ord
			else
				byte = str[0]
			end
			self[:urg] = byte & 0b00100000 == 0b00100000 ? 1 : 0
			self[:ack] = byte & 0b00010000 == 0b00010000 ? 1 : 0
			self[:psh] = byte & 0b00001000 == 0b00001000 ? 1 : 0
			self[:rst] = byte & 0b00000100 == 0b00000100 ? 1 : 0
			self[:syn] = byte & 0b00000010 == 0b00000010 ? 1 : 0
			self[:fin] = byte & 0b00000001 == 0b00000001 ? 1 : 0
			self
		end

	end

end

module PacketFu

	# TcpOption is the base class for all TCP options. Note that TcpOption#len 
	# returns the size of the entire option, while TcpOption#optlen is the struct 
	# for the TCP Option Length field.
	#
	# Subclassed options should set the correct TcpOption#kind by redefining 
	# initialize. They should also deal with various value types there by setting
	# them explicitly with an accompanying StructFu#typecast for the setter. 
	#
	# By default, values are presumed to be strings, unless they are Numeric, in
	# which case a guess is made to the width of the Numeric based on the given
	# optlen. 
	#
	# Note that normally, optlen is /not/ enforced for directly setting values,
	# so the user is perfectly capable of setting incorrect lengths.
	class TcpOption < Struct.new(:kind, :optlen, :value)

		include StructFu

		def initialize(args={})
			super(
				Int8.new(args[:kind]),
				Int8.new(args[:optlen])
			)
			if args[:value].kind_of? Numeric
				self[:value] = case args[:optlen]
											 when 3; Int8.new(args[:value])
											 when 4; Int16.new(args[:value])
											 when 6; Int32.new(args[:value])
											 else; StructFu::String.new.read(args[:value])
											 end
			else
				self[:value] = StructFu::String.new.read(args[:value])
			end
		end

		# Returns the object in string form.
		def to_s
			self[:kind].to_s + 
			(self[:optlen].value.nil? ? nil : self[:optlen]).to_s +
			(self[:value].nil? ? nil : self[:value]).to_s
		end

		# Reads a string to populate the object.
		def read(str)
			force_binary(str)
			return self if str.nil?
			self[:kind].read(str[0,1])
			if str[1,1]
				self[:optlen].read(str[1,1])
				if str[2,1] && optlen.value > 2
					self[:value].read(str[2,optlen.value-2])
				end
			end
			self
		end

		# The default decode for an unknown option. Known options should redefine this.
		def decode
			unk = "unk-#{self.kind.to_i}"
			(self[:optlen].to_i > 2 && self[:value].to_s.size > 1) ? [unk,self[:value]].join(":") : unk
		end

		# Setter for the "kind" byte of this option.
		def kind=(i); typecast i; end
		# Setter for the "option length" byte for this option.
		def optlen=(i); typecast i; end

		# Setter for the value of this option. 
		def value=(i)
			if i.kind_of? Numeric
				typecast i
			elsif i.respond_to? :to_s
				self[:value] = i
			else
				self[:value] = ''
			end
		end

		# Generally, encoding a value is going to be just a read. Some
		# options will treat things a little differently; TS for example,
		# takes two values and concatenates them.
		def encode(str)
			self[:value] = self.class.new(:value => str).value
		end

		# Returns true if this option has an optlen. Some don't.
		def has_optlen?
			(kind.value && kind.value < 2) ? false : true
		end
		
		# Returns true if this option has a value. Some don't.
		def has_value?
			(value.respond_to? :to_s && value.to_s.size > 0) ? false : true
		end

		# End of Line option. Usually used to terminate a string of options.
		#
		# http://www.networksorcery.com/enp/protocol/tcp/option000.htm
		class EOL < TcpOption
			def initialize(args={})
				super(
					args.merge(:kind => 0)
				)
			end

			def decode
				"EOL"
			end

		end

		# No Operation option. Usually used to pad out options to fit a 4-byte alignment.
		#
		# http://www.networksorcery.com/enp/protocol/tcp/option001.htm
		class NOP < TcpOption
			def initialize(args={})
				super(
					args.merge(:kind => 1)
				)
			end

			def decode
				"NOP"
			end

		end

		# Maximum Segment Size option.
		#
		# http://www.networksorcery.com/enp/protocol/tcp/option002.htm
		class MSS < TcpOption
			def initialize(args={})
				super(
					args.merge(:kind => 2,
										 :optlen => 4
										)
				)
				self[:value] = Int16.new(args[:value])
			end

			def value=(i); typecast i; end

			# MSS options with lengths other than 4 are malformed.
			def decode
				if self[:optlen].to_i == 4
					"MSS:#{self[:value].to_i}"
				else
					"MSS-bad:#{self[:value]}"
				end
			end

		end

		# Window Size option.
		#
		# http://www.networksorcery.com/enp/protocol/tcp/option003.htm
		class WS < TcpOption
			def initialize(args={})
				super(
					args.merge(:kind => 3,
										 :optlen => 3
										)
				)
				self[:value] = Int8.new(args[:value])
			end

			def value=(i); typecast i; end

			# WS options with lengths other than 3 are malformed.
			def decode
				if self[:optlen].to_i == 3
					"WS:#{self[:value].to_i}"
				else
					"WS-bad:#{self[:value]}"
				end
			end

		end

		# Selective Acknowlegment OK option.
		#
		# http://www.networksorcery.com/enp/protocol/tcp/option004.htm
		class SACKOK < TcpOption
			def initialize(args={})
				super(
					args.merge(:kind => 4,
										 :optlen => 2)
				)
			end

			# SACKOK options with sizes other than 2 are malformed.
			def decode
				if self[:optlen].to_i == 2
					"SACKOK"
				else
					"SACKOK-bad:#{self[:value]}"
				end
			end

		end

		# Selective Acknowledgement option.
		#
		# http://www.networksorcery.com/enp/protocol/tcp/option004.htm
		#
		# Note that SACK always takes its optlen from the size of the string.
		class SACK < TcpOption
			def initialize(args={})
				super(
					args.merge(:kind => 5,
										 :optlen => ((args[:value] || "").size + 2)
										)
				)
			end

			def optlen=(i); typecast i; end

			def value=(i)
				self[:optlen] = Int8.new(i.to_s.size + 2)
				self[:value] = StructFu::String.new(i)
			end

			def decode
					"SACK:#{self[:value]}"
			end

			def encode(str)
				temp_obj = self.class.new(:value => str)
				self[:value] = temp_obj.value
				self[:optlen] = temp_obj.optlen.value
				self
			end

		end

		# Echo option.
		#
		# http://www.networksorcery.com/enp/protocol/tcp/option006.htm
		class ECHO < TcpOption
			def initialize(args={})
				super(
					args.merge(:kind => 6,
										 :optlen => 6
										)
				)
			end

			# ECHO options with lengths other than 6 are malformed.
			def decode
				if self[:optlen].to_i == 6
					"ECHO:#{self[:value]}"
				else
					"ECHO-bad:#{self[:value]}"
				end
			end

		end

		# Echo Reply option.
		#
		# http://www.networksorcery.com/enp/protocol/tcp/option007.htm
		class ECHOREPLY < TcpOption
			def initialize(args={})
				super(
					args.merge(:kind => 7,
										 :optlen => 6
										)
				)
			end

			# ECHOREPLY options with lengths other than 6 are malformed.
			def decode
				if self[:optlen].to_i == 6
					"ECHOREPLY:#{self[:value]}"
				else
					"ECHOREPLY-bad:#{self[:value]}"
				end
			end

		end

		# Timestamp option
		#
		# http://www.networksorcery.com/enp/protocol/tcp/option008.htm
		class TS < TcpOption
			def initialize(args={})
				super(
					args.merge(:kind => 8,
										 :optlen => 10
										)
				)
				self[:value] = StructFu::String.new.read(args[:value] || "\x00" * 8) 
			end

			# TS options with lengths other than 10 are malformed.
			def decode
				if self[:optlen].to_i == 10
					val1,val2 = self[:value].unpack("NN")
					"TS:#{val1};#{val2}"
				else
					"TS-bad:#{self[:value]}"
				end
			end

			# TS options are in the format of "TS:[timestamp value];[timestamp secret]" Both
			# should be written as decimal numbers.
			def encode(str)
				if str =~ /^([0-9]+);([0-9]+)$/
					tsval,tsecr = str.split(";").map {|x| x.to_i}
					if tsval <= 0xffffffff && tsecr <= 0xffffffff
						self[:value] = StructFu::String.new([tsval,tsecr].pack("NN"))
					else
						self[:value] = StructFu::String.new(str)
					end
				else
					self[:value] = StructFu::String.new(str)
				end
			end

		end

	end

	class TcpOptions < Array

		include StructFu

		# If args[:pad] is set, the options line is automatically padded out
		# with NOPs. 
		def to_s(args={})
			opts = self.map {|x| x.to_s}.join
			if args[:pad]
				unless (opts.size % 4).zero?
					(4 - (opts.size % 4)).times { opts << "\x01" }
				end
			end
			opts
		end

		# Reads a string to populate the object.
		def read(str)
			self.clear 
			PacketFu.force_binary(str)
			return self if(!str.respond_to? :to_s || str.nil?)
			i = 0
			while i < str.to_s.size
				this_opt = case str[i,1].unpack("C").first
									 when 0; TcpOption::EOL.new
									 when 1; TcpOption::NOP.new
									 when 2; TcpOption::MSS.new
									 when 3; TcpOption::WS.new
									 when 4; TcpOption::SACKOK.new
									 when 5; TcpOption::SACK.new
									 when 6; TcpOption::ECHO.new
									 when 7; TcpOption::ECHOREPLY.new
									 when 8; TcpOption::TS.new
									 else; TcpOption.new
									 end
				this_opt.read str[i,str.size]
				unless this_opt.has_optlen?
					this_opt.value = nil
					this_opt.optlen = nil
				end
				self << this_opt
				i += this_opt.sz
			end
			self
		end

		# Decode parses the TcpOptions object's member options, and produces a
		# human-readable string by iterating over each element's decode() function.
		# If TcpOptions elements were not initially created as TcpOptions, an
		# attempt will be made to convert them. 
		#
		# The output of decode is suitable as input for TcpOptions#encode.
		def decode
			decoded = self.map do |x| 
				if x.kind_of? TcpOption
					x.decode
				else
					x = TcpOptions.new.read(x).decode
				end
			end
			decoded.join(",")
		end

		# Encode takes a human-readable string and appends the corresponding
		# binary options to the TcpOptions object. To completely replace the contents
		# of the object, use TcpOptions#encode! instead.
		# 
		# Options are comma-delimited, and are identical to the output of the
		# TcpOptions#decode function. Note that the syntax can be unforgiving, so
		# it may be easier to create the subclassed TcpOptions themselves directly,
		# but this method can be less typing if you know what you're doing.
		# 
		# Note that by using TcpOptions#encode, strings supplied as values which
		# can be converted to numbers will be converted first.
		#
		# === Example
		#
		#   t = TcpOptions.new
		#   t.encode("MS:1460,WS:6")
		#		t.to_s # => "\002\004\005\264\002\003\006"
		#		t.encode("NOP")
		#		t.to_s # => "\002\004\005\264\002\003\006\001"
		def encode(str)
			opts = str.split(/[\s]*,[\s]*/)
			opts.each do |o|
				kind,value = o.split(/[\s]*:[\s]*/)
				klass = TcpOption.const_get(kind.upcase)
				value = value.to_i if value =~ /^[0-9]+$/
				this_opt = klass.new
				this_opt.encode(value)
				self << this_opt
			end
			self
		end

		# Like TcpOption#encode, except the entire contents are replaced.
		def encode!(str)
			self.clear if self.size > 0
			encode(str)
		end

	end

end

module PacketFu

	# TCPHeader is a complete TCP struct, used in TCPPacket. Most IP traffic is TCP-based, by
	# volume.
	#
	# For more on TCP packets, see http://www.networksorcery.com/enp/protocol/tcp.htm
	#
	# ==== Header Definition
	# 
	#   Int16        :tcp_src       Default: random 
	#   Int16        :tcp_dst
	#   Int32        :tcp_seq       Default: random
	#   Int32        :tcp_ack
	#   TcpHlen      :tcp_hlen      Default: 5           # Must recalc as options are set. 
	#   TcpReserved  :tcp_reserved  Default: 0
	#   TcpEcn       :tcp_ecn
	#   TcpFlags     :tcp_flags
	#   Int16        :tcp_win,      Default: 0           # WinXP's default syn packet
	#   Int16        :tcp_sum,      Default: calculated  # Must set this upon generation.
	#   Int16        :tcp_urg
	#   TcpOptions   :tcp_opts
	#   String       :body
	#
	# See also TcpHlen, TcpReserved, TcpEcn, TcpFlags, TcpOpts
	class TCPHeader < Struct.new(:tcp_src, :tcp_dst,
															 :tcp_seq,
															 :tcp_ack,
															 :tcp_hlen, :tcp_reserved, :tcp_ecn, :tcp_flags, :tcp_win, 
															 :tcp_sum, :tcp_urg, 
															 :tcp_opts, :body)
		include StructFu

		def initialize(args={})
			@random_seq = rand(0xffffffff)
			@random_src = rand_port
			super(
				Int16.new(args[:tcp_src] || tcp_calc_src),
				Int16.new(args[:tcp_dst]),
				Int32.new(args[:tcp_seq] || tcp_calc_seq),
				Int32.new(args[:tcp_ack]),
				TcpHlen.new(:hlen => (args[:tcp_hlen] || 5)),
				TcpReserved.new(args[:tcp_reserved] || 0),
				TcpEcn.new(args[:tcp_ecn]),
				TcpFlags.new(args[:tcp_flags]),
				Int16.new(args[:tcp_win] || 0x4000),
				Int16.new(args[:tcp_sum] || 0),
				Int16.new(args[:tcp_urg]),
				TcpOptions.new.read(args[:tcp_opts]),
				StructFu::String.new.read(args[:body])
			)
		end

		attr_accessor :flavor

		# Helper function to create the string for Hlen, Reserved, ECN, and Flags.
		def bits_to_s
			bytes = []
			bytes[0] = (self[:tcp_hlen].to_i << 4) +
				(self[:tcp_reserved].to_i << 1) +
				self[:tcp_ecn].n.to_i
			bytes[1] = (self[:tcp_ecn].c.to_i << 7) +
				(self[:tcp_ecn].e.to_i << 6) +
				self[:tcp_flags].to_i
			bytes.pack("CC")
		end

		# Returns the object in string form.
		def to_s
			hdr = self.to_a.map do |x|
				if x.kind_of? TcpHlen
					bits_to_s
				elsif x.kind_of? TcpReserved
					next
				elsif x.kind_of? TcpEcn
					next
				elsif x.kind_of? TcpFlags
					next
				else
					x.to_s
				end
			end
			hdr.flatten.join
		end

		# Reads a string to populate the object.
		def read(str)
			force_binary(str)
			return self if str.nil?
			self[:tcp_src].read(str[0,2])
			self[:tcp_dst].read(str[2,2])
			self[:tcp_seq].read(str[4,4])
			self[:tcp_ack].read(str[8,4])
			self[:tcp_hlen].read(str[12,1])
			self[:tcp_reserved].read(str[12,1])
			self[:tcp_ecn].read(str[12,2])
			self[:tcp_flags].read(str[13,1])
			self[:tcp_win].read(str[14,2])
			self[:tcp_sum].read(str[16,2])
			self[:tcp_urg].read(str[18,2])
			self[:tcp_opts].read(str[20,((self[:tcp_hlen].to_i * 4) - 20)])
			self[:body].read(str[(self[:tcp_hlen].to_i * 4),str.size])
			self
		end

		# Setter for the TCP source port.
		def tcp_src=(i); typecast i; end
		# Getter for the TCP source port.
		def tcp_src; self[:tcp_src].to_i; end
		# Setter for the TCP destination port.
		def tcp_dst=(i); typecast i; end
		# Getter for the TCP destination port.
		def tcp_dst; self[:tcp_dst].to_i; end
		# Setter for the TCP sequence number.
		def tcp_seq=(i); typecast i; end
		# Getter for the TCP sequence number.
		def tcp_seq; self[:tcp_seq].to_i; end
		# Setter for the TCP ackowlegement number.
		def tcp_ack=(i); typecast i; end
		# Getter for the TCP ackowlegement number.
		def tcp_ack; self[:tcp_ack].to_i; end
		# Setter for the TCP window size number.
		def tcp_win=(i); typecast i; end
		# Getter for the TCP window size number.
		def tcp_win; self[:tcp_win].to_i; end
		# Setter for the TCP checksum.
		def tcp_sum=(i); typecast i; end
		# Getter for the TCP checksum.
		def tcp_sum; self[:tcp_sum].to_i; end
		# Setter for the TCP urgent field.
		def tcp_urg=(i); typecast i; end
		# Getter for the TCP urgent field.
		def tcp_urg; self[:tcp_urg].to_i; end

		# Getter for the TCP Header Length value.
		def tcp_hlen; self[:tcp_hlen].to_i; end
		# Setter for the TCP Header Length value. Can take
		# either a string or an integer. Note that if it's
		# a string, the top four bits are used.
		def tcp_hlen=(i)
			case i
			when PacketFu::TcpHlen
				self[:tcp_hlen] = i
			when Numeric
				self[:tcp_hlen] = TcpHlen.new(:hlen => i.to_i)
			else
				self[:tcp_hlen].read(i)
			end
		end

		# Getter for the TCP Reserved field.
		def tcp_reserved; self[:tcp_reserved].to_i; end
		# Setter for the TCP Reserved field.
		def tcp_reserved=(i)
			case i
			when PacketFu::TcpReserved
				self[:tcp_reserved]=i
			when Numeric
				args = {}
				args[:r1] = (i & 0b100) >> 2
				args[:r2] = (i & 0b010) >> 1
				args[:r3] = (i & 0b001)
				self[:tcp_reserved] = TcpReserved.new(args)
			else
				self[:tcp_reserved].read(i)
			end
		end

		# Getter for the ECN bits. 
		def tcp_ecn; self[:tcp_ecn].to_i; end
		# Setter for the ECN bits. 
		def tcp_ecn=(i)
			case i
			when PacketFu::TcpEcn
				self[:tcp_ecn]=i
			when Numeric
				args = {}
				args[:n] = (i & 0b100) >> 2
				args[:c] = (i & 0b010) >> 1
				args[:e] = (i & 0b001)
				self[:tcp_ecn] = TcpEcn.new(args)
			else
				self[:tcp_ecn].read(i)
			end
		end

		# Getter for TCP Options.
		def tcp_opts; self[:tcp_opts].to_s; end
		# Setter for TCP Options.
		def tcp_opts=(i)
			case i
			when PacketFu::TcpOptions
				self[:tcp_opts]=i
			else
				self[:tcp_opts].read(i)
			end
		end

		# Resets the sequence number to a new random number.
		def tcp_calc_seq; @random_seq; end
		# Resets the source port to a new random number.
		def tcp_calc_src; @random_src; end

		# Returns the actual length of the TCP options.
		def tcp_opts_len
			self[:tcp_opts].to_s.size
		end

		# Sets and returns the true length of the TCP Header.
		# TODO: Think about making all the option stuff safer. 
		def tcp_calc_hlen
			self[:tcp_hlen] = TcpHlen.new(:hlen => ((20 + tcp_opts_len) / 4))
		end

		# Generates a random high port. This is affected by packet flavor.
		def rand_port
			rand(0xffff - 1025) + 1025
		end

		# Gets a more readable option list.
		def tcp_options
		 self[:tcp_opts].decode
		end

		# Gets a more readable flags list
		def tcp_flags_dotmap
			dotmap = tcp_flags.members.map do |flag|
				status = self.tcp_flags.send flag
				status == 0 ? "." : flag.to_s.upcase[0].chr
			end
			dotmap.join
		end

		# Sets a more readable option list.
		def tcp_options=(arg)
			self[:tcp_opts].encode arg
		end

		# Equivalent to tcp_src.
		def tcp_sport
			self.tcp_src.to_i
		end

		# Equivalent to tcp_src=.
		def tcp_sport=(arg)
			self.tcp_src=(arg)
		end

		# Equivalent to tcp_dst.
		def tcp_dport
			self.tcp_dst.to_i
		end
		
		# Equivalent to tcp_dst=.
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

		# Readability aliases

		alias :tcp_flags_readable :tcp_flags_dotmap

		def tcp_ack_readable
			"0x%08x" % tcp_ack
		end

		def tcp_seq_readable
			"0x%08x" % tcp_seq
		end

		def tcp_sum_readable
			"0x%04x" % tcp_sum
		end

		def tcp_opts_readable
			tcp_options
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

		attr_accessor :eth_header, :ip_header, :tcp_header

		def self.can_parse?(str)
			return false unless str.size >= 54
			return false unless EthPacket.can_parse? str
			return false unless IPPacket.can_parse? str
			return false unless str[23,1] == "\x06"
			return true
		end

		def read(str=nil, args={})
			raise "Cannot parse `#{str}'" unless self.class.can_parse?(str)
			@eth_header.read(str)
			@ip_header.read(str[14,str.size])
			@eth_header.body = @ip_header
			if args[:strip]
				tcp_len = str[16,2].unpack("n")[0] - 20
				@tcp_header.read(str[14+(@ip_header.ip_hlen),tcp_len])
			else
				@tcp_header.read(str[14+(@ip_header.ip_hlen),str.size])
			end
			@ip_header.body = @tcp_header
			super(args)
			self
		end

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
				@tcp_header.tcp_options="MSS:1460,NOP,NOP,SACKOK"
				@tcp_header.tcp_src = rand(5000 - 1026) + 1026
				@ip_header.ip_ttl = 64
			when "linux" # Ubuntu Linux 2.6.24-19-generic default syn
				@tcp_header.tcp_win = 5840
				@tcp_header.tcp_options="MSS:1460,SACKOK,TS:#{ts_val};0,NOP,WS:7"
				@tcp_header.tcp_src = rand(61_000 - 32_000) + 32_000
				@ip_header.ip_ttl = 64
			when "freebsd" # Freebsd
				@tcp_header.tcp_win = 0xffff
				@tcp_header.tcp_options="MSS:1460,NOP,WS:3,NOP,NOP,TS:#{ts_val};#{ts_sec},SACKOK,EOL,EOL"
				@ip_header.ip_ttl = 64
			else
				@tcp_header.tcp_options="MSS:1460,NOP,NOP,SACKOK"
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
			chk_tcp_opts.unpack("n*").each {|x| checksum = checksum + x }
			if (ip_len - ((ip_hl + tcp_hlen) * 4)) >= 0
				real_tcp_payload = payload[0,( ip_len - ((ip_hl + tcp_hlen) * 4) )] # Can't forget those pesky FCSes!
			else
				real_tcp_payload = payload # Something's amiss here so don't bother figuring out where the real payload is.
			end
			chk_payload = (real_tcp_payload.size % 2 == 0 ? real_tcp_payload : real_tcp_payload + "\x00") # Null pad if it's odd.
			chk_payload.unpack("n*").each {|x| checksum = checksum+x }
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

		# TCP packets are denoted by a "T  ", followed by size,
		# source and dest information, packet flags, sequence
		# number, and IPID.
		def peek_format
			peek_data = ["T  "]
			peek_data << "%-5d" % self.to_s.size
			peek_data << "%-21s" % "#{self.ip_saddr}:#{self.tcp_src}"
			peek_data << "->"
			peek_data << "%21s" % "#{self.ip_daddr}:#{self.tcp_dst}"
			flags = ' ['
			flags << self.tcp_flags_dotmap
			flags << '] '
			peek_data << flags
			peek_data << "S:"
			peek_data << "%08x" % self.tcp_seq
			peek_data << "|I:"
			peek_data << "%04x" % self.ip_id
			peek_data.join
		end

	end

end
