#!/usr/bin/env ruby
# -*- coding: binary -*-

module StructFu

	# Set the endianness for the various Int classes. Takes either :little or :big.
	def set_endianness(e=nil)
		unless [:little, :big].include? e
			raise ArgumentError, "Unknown endianness for #{self.class}" 
		end
		@int32 = e == :little ? Int32le : Int32be
		@int16 = e == :little ? Int16le : Int16be
		return e
	end

	# Instead of returning the "size" of the object, which is usually the
	# number of elements of the Struct, returns the size of the object after
	# a to_s. Essentially, a short version of self.to_size.size
	def sz
		self.to_s.size
	end

end

module PacketFu

	# PcapHeader represents the header portion of a libpcap file (the packets
	# themselves are in the PcapPackets array). See 
	# http://wiki.wireshark.org/Development/LibpcapFileFormat for details.
	#
	# Depending on the endianness (set with :endian), elements are either
	# :little endian or :big endian. 
	#
	# ==== PcapHeader Definition
	#
	#   Symbol  :endian     Default: :little
	#   Int32   :magic      Default: 0xa1b2c3d4 # :big is 0xd4c3b2a1
	#   Int16   :ver_major  Default: 2
	#   Int16   :ver_minor  Default: 4
	#   Int32   :thiszone
	#   Int32   :sigfigs
	#   Int32   :snaplen    Default: 0xffff
	#   Int32   :network    Default: 1
	class PcapHeader < Struct.new(:endian, :magic, :ver_major, :ver_minor,
																:thiszone, :sigfigs, :snaplen, :network)
		include StructFu

		MAGIC_INT32  = 0xa1b2c3d4
		MAGIC_LITTLE = [MAGIC_INT32].pack("V")
		MAGIC_BIG    = [MAGIC_INT32].pack("N")

		def initialize(args={})
			set_endianness(args[:endian] ||= :little)
			init_fields(args) 
			super(args[:endian], args[:magic], args[:ver_major], 
						args[:ver_minor], args[:thiszone], args[:sigfigs], 
						args[:snaplen], args[:network])
		end
		
		# Called by initialize to set the initial fields. 
		def init_fields(args={})
			args[:magic] = @int32.new(args[:magic] || PcapHeader::MAGIC_INT32)
			args[:ver_major] = @int16.new(args[:ver_major] || 2)
			args[:ver_minor] ||= @int16.new(args[:ver_minor] || 4)
			args[:thiszone] ||= @int32.new(args[:thiszone])
			args[:sigfigs] ||= @int32.new(args[:sigfigs])
			args[:snaplen] ||= @int32.new(args[:snaplen] || 0xffff)
			args[:network] ||= @int32.new(args[:network] || 1)
			return args
		end

		# Returns the object in string form.
		def to_s
			self.to_a[1,7].map {|x| x.to_s}.join
		end

		# Reads a string to populate the object.
		# TODO: Need to test this by getting a hold of a big endian pcap file.
		# Conversion from big to little shouldn't be that big of a deal.
		def read(str)
			force_binary(str)
			return self if str.nil?
			str.force_encoding("binary") if str.respond_to? :force_encoding
			if str[0,4] == self[:magic].to_s 
				self[:magic].read str[0,4]
				self[:ver_major].read str[4,2]
				self[:ver_minor].read str[6,2]
				self[:thiszone].read str[8,4]
				self[:sigfigs].read str[12,4]
				self[:snaplen].read str[16,4]
				self[:network].read str[20,4]
			else
				raise "Incorrect magic for libpcap"
			end
			self
		end

	end

	# The Timestamp class defines how Timestamps appear in libpcap files.
	#
	# ==== Header Definition
	#
	#  Symbol  :endian  Default: :little
	#  Int32   :sec
	#  Int32   :usec
	class Timestamp < Struct.new(:endian, :sec, :usec)
		include StructFu

		def initialize(args={})
			set_endianness(args[:endian] ||= :little)
			init_fields(args)
			super(args[:endian], args[:sec], args[:usec])
		end

		# Called by initialize to set the initial fields. 
		def init_fields(args={})
			args[:sec] = @int32.new(args[:sec])
			args[:usec] = @int32.new(args[:usec])
			return args
		end

		# Returns the object in string form.
		def to_s
			self.to_a[1,2].map {|x| x.to_s}.join
		end

		# Reads a string to populate the object.
		def read(str)
			force_binary(str)
			return self if str.nil?
			self[:sec].read str[0,4]
			self[:usec].read str[4,4]
			self
		end

	end

	# PcapPacket defines how individual packets are stored in a libpcap-formatted
	# file.
	#
	# ==== Header Definition
	#
	# Timestamp  :timestamp
	# Int32      :incl_len
	# Int32      :orig_len
	# String     :data
	class PcapPacket < Struct.new(:endian, :timestamp, :incl_len,
															 :orig_len, :data)
		include StructFu
		def initialize(args={})
			set_endianness(args[:endian] ||= :little)
			init_fields(args)
			super(args[:endian], args[:timestamp], args[:incl_len],
					 args[:orig_len], args[:data])
		end

		# Called by initialize to set the initial fields. 
		def init_fields(args={})
			args[:timestamp] = Timestamp.new(:endian => args[:endian]).read(args[:timestamp])
			args[:incl_len] = args[:incl_len].nil? ? @int32.new(args[:data].to_s.size) : @int32.new(args[:incl_len])
			args[:orig_len] = @int32.new(args[:orig_len])
			args[:data] = StructFu::String.new.read(args[:data])
		end

		# Returns the object in string form.
		def to_s
			self.to_a[1,4].map {|x| x.to_s}.join
		end

		# Reads a string to populate the object.
		def read(str)
			return unless str
			force_binary(str)
			self[:timestamp].read str[0,8]
			self[:incl_len].read str[8,4]
			self[:orig_len].read str[12,4]
			self[:data].read str[16,self[:incl_len].to_i]
			self
		end

	end

	# PcapPackets is a collection of PcapPacket objects.
	class PcapPackets < Array

		include StructFu

		attr_accessor :endian # probably ought to be read-only but who am i.

		def initialize(args={})
			@endian = args[:endian] || :little
		end

		def force_binary(str)
			str.force_encoding "binary" if str.respond_to? :force_encoding
		end

		# Reads a string to populate the object. Note, this read takes in the 
		# whole pcap file, since we need to see the magic to know what 
		# endianness we're dealing with.
		def read(str)
			force_binary(str)
			return self if str.nil?
			if str[0,4] == PcapHeader::MAGIC_BIG
				@endian = :big
			elsif str[0,4] == PcapHeader::MAGIC_LITTLE
				@endian = :little
			else
				raise ArgumentError, "Unknown file format for #{self.class}"
			end
			body = str[24,str.size]
			while body.size > 16 # TODO: catch exceptions on malformed packets at end
				p = PcapPacket.new(:endian => @endian)
				p.read(body)
				self<<p
				body = body[p.sz,body.size]
			end
		self
		end

		def to_s
			self.join
		end

	end

	# PcapFile is a complete libpcap file struct, made up of two elements, a 
	# PcapHeader and PcapPackets.
	#
	# See http://wiki.wireshark.org/Development/LibpcapFileFormat
	#
	# PcapFile also can behave as a singleton class, which is usually the better
	# way to handle pcap files of really any size, since it doesn't require
	# storing packets before handing them off to a given block. This is really
	# the way to go.
	class PcapFile < Struct.new(:endian, :head, :body)
		include StructFu

		class << self

			# Takes a given file and returns an array of the packet bytes. Here 
			# for backwards compatibilty.
			def file_to_array(fname)
				PcapFile.new.file_to_array(:f => fname)
			end

			# Takes a given file name, and reads out the packets. If given a block,
			# it will yield back a PcapPacket object per packet found.
			def read(fname,&block) 
				file_header = PcapHeader.new
				pcap_packets = PcapPackets.new 
				unless File.readable? fname
					raise ArgumentError, "Cannot read file `#{fname}'"
				end
				begin
				file_handle = File.open(fname, "rb")
				file_header.read file_handle.read(24)
				packet_count = 0
				pcap_packet = PcapPacket.new(:endian => file_header.endian)
				while pcap_packet.read file_handle.read(16) do
					len = pcap_packet.incl_len
					pcap_packet.data = StructFu::String.new.read(file_handle.read(len.to_i))
					packet_count += 1
					if pcap_packet.data.size < len.to_i
						warn "Packet ##{packet_count} is corrupted: expected #{len.to_i}, got #{pcap_packet.data.size}. Exiting."
						break
					end
					if block
						yield pcap_packet
					else
						pcap_packets << pcap_packet.clone
					end
				end
				ensure
					file_handle.close
				end
				block ? packet_count : pcap_packets
			end

			# Takes a filename, and an optional block. If a block is given, 
			# yield back the raw packet data from the given file. Otherwise,
			# return an array of parsed packets.
			def read_packet_bytes(fname,&block)
				count = 0
				packets = [] unless block
				read(fname) do |packet| 
					if block
						count += 1
						yield packet.data.to_s
					else
						packets << packet.data.to_s
					end
				end
				block ? count : packets
			end

			alias :file_to_array :read_packet_bytes 

			# Takes a filename, and an optional block. If a block is given,
			# yield back parsed packets from the given file. Otherwise, return
			# an array of parsed packets.
			#
			# This is a brazillian times faster than the old methods of extracting
			# packets from files.
			def read_packets(fname,&block)
				count = 0
				packets = [] unless block
				read_packet_bytes(fname) do |packet| 
					if block
						count += 1
						yield Packet.parse(packet)
					else
						packets << Packet.parse(packet)
					end
				end
				block ? count : packets
			end

		end

		def initialize(args={})
			init_fields(args)
			@filename = args.delete :filename
			super(args[:endian], args[:head], args[:body])
		end

		# Called by initialize to set the initial fields. 
		def init_fields(args={})
			args[:head] = PcapHeader.new(:endian => args[:endian]).read(args[:head])
			args[:body] = PcapPackets.new(:endian => args[:endian]).read(args[:body])
			return args
		end

		# Returns the object in string form.
		def to_s
			self[:head].to_s + self[:body].map {|p| p.to_s}.join
		end

		# Clears the contents of the PcapFile.
		def clear
			self[:body].clear
		end

		# Reads a string to populate the object. Note that this appends new packets to
		# any existing packets in the PcapFile.
		def read(str)
			force_binary(str)
			self[:head].read str[0,24]
			self[:body].read str
			self
		end

		# Clears the contents of the PcapFile prior to reading in a new string.
		def read!(str)
			clear	
			force_binary(str)
			self.read str
		end

		# A shorthand method for opening a file and reading in the packets. Note
		# that readfile clears any existing packets, since that seems to be the
		# typical use.
		def readfile(file)
			fdata = File.open(file, "rb") {|f| f.read}
			self.read! fdata
		end

		# Calls the class method with this object's @filename
		def read_packet_bytes(fname=@filename,&block)
			raise ArgumentError, "Need a file" unless fname
			return self.class.read_packet_bytes(fname, &block)
		end

		# Calls the class method with this object's @filename
		def read_packets(fname=@filename,&block)
			raise ArgumentError, "Need a file" unless fname
			return self.class.read_packets(fname, &block)
		end

		# file_to_array() translates a libpcap file into an array of packets.
		# Note that this strips out pcap timestamps -- if you'd like to retain
		# timestamps and other libpcap file information, you will want to 
		# use read() instead.
		def file_to_array(args={})
			filename = args[:filename] || args[:file] || args[:f]
			if filename
				self.read! File.open(filename, "rb") {|f| f.read}
			end
			if args[:keep_timestamps] || args[:keep_ts] || args[:ts]
				self[:body].map {|x| {x.timestamp.to_s => x.data.to_s} }
			else
				self[:body].map {|x| x.data.to_s}
			end
		end

		alias_method :f2a, :file_to_array

		# Takes an array of packets (as generated by file_to_array), and writes them
		# to a file. Valid arguments are:
		#
		#   :filename
		#   :array      # Can either be an array of packet data, or a hash-value pair of timestamp => data.
		#   :timestamp  # Sets an initial timestamp
		#   :ts_inc     # Sets the increment between timestamps. Defaults to 1 second.
		#   :append     # If true, then the packets are appended to the end of a file.
		def array_to_file(args={})
			if args.kind_of? Hash
				filename = args[:filename] || args[:file] || args[:f]
				arr = args[:array] || args[:arr] || args[:a]
				ts = args[:timestamp] || args[:ts] || Time.now.to_i
				ts_inc = args[:timestamp_increment] || args[:ts_inc] || 1
				append = !!args[:append]
			elsif args.kind_of? Array
				arr = args
				filename = append = nil
			else
				raise ArgumentError, "Unknown argument. Need either a Hash or Array."
			end
			unless arr.kind_of? Array
				raise ArgumentError, "Need an array to read packets from"
			end
			arr.each_with_index do |p,i|
				if p.kind_of? Hash # Binary timestamps are included
					this_ts = p.keys.first
					this_incl_len = p.values.first.size
					this_orig_len = this_incl_len
					this_data = p.values.first
				else # it's an array
					this_ts = Timestamp.new(:endian => self[:endian], :sec => ts + (ts_inc * i)).to_s
					this_incl_len = p.to_s.size
					this_orig_len = this_incl_len
					this_data = p.to_s
				end
				this_pkt = PcapPacket.new({:endian => self[:endian],
																  :timestamp => this_ts,
																	:incl_len => this_incl_len,
																	:orig_len => this_orig_len,
																	:data => this_data }
																 )
				self[:body] << this_pkt
			end
			if filename
				self.to_f(:filename => filename, :append => append)
			else
				self
			end
		end

		alias_method :a2f, :array_to_file

		# Just like array_to_file, but clears any existing packets from the array first.
		def array_to_file!(arr)
			clear
			array_to_file(arr)
		end

		alias_method :a2f!, :array_to_file!

		# Writes the PcapFile to a file. Takes the following arguments:
		#
		#   :filename # The file to write to.
		#   :append   # If set to true, the packets are appended to the file, rather than overwriting.
		def to_file(args={})
			filename = args[:filename] || args[:file] || args[:f]
			unless (!filename.nil? || filename.kind_of?(String))
				raise ArgumentError, "Need a :filename for #{self.class}"
			end
			append = args[:append]
			if append
				if File.exists? filename
					File.open(filename,'ab') {|file| file.write(self.body.to_s)}
				else
					File.open(filename,'wb') {|file| file.write(self.to_s)}
				end
			else
				File.open(filename,'wb') {|file| file.write(self.to_s)}
			end
			[filename, self.body.sz, self.body.size]
		end

		alias_method :to_f, :to_file

		# Shorthand method for writing to a file. Can take either :file => 'name.pcap' or
		# simply 'name.pcap'
		def write(filename='out.pcap')
			if filename.kind_of?(Hash)
				f = filename[:filename] || filename[:file] || filename[:f] || 'out.pcap'
			else
				f = filename.to_s
			end
			self.to_file(:filename => f.to_s, :append => false)
		end

		# Shorthand method for appending to a file. Can take either :file => 'name.pcap' or
		# simply 'name.pcap'
		def append(filename='out.pcap')
			if filename.kind_of?(Hash)
				f = filename[:filename] || filename[:file] || filename[:f] || 'out.pcap'
			else
				f = filename.to_s
			end
			self.to_file(:filename => f, :append => true)
		end

	end

end

module PacketFu

	# Read is largely deprecated. It was current in PacketFu 0.2.0, but isn't all that useful
	# in 0.3.0 and beyond. Expect it to go away completely by version 1.0. So, the main use
	# of this class is to learn how to do exactly the same things using the PcapFile object.
	class Read

		class << self

			# Reads the magic string of a pcap file, and determines
			# if it's :little or :big endian.
			def get_byte_order(pcap_file)
				byte_order = ((pcap_file[0,4] == PcapHeader::MAGIC_LITTLE) ? :little : :big)
				return byte_order
			end

			# set_byte_order is pretty much totally deprecated.
			def set_byte_order(byte_order)
				PacketFu.instance_variable_set(:@byte_order,byte_order)
				return true
			end

			# A wrapper for PcapFile#file_to_array, but only returns the array. Actually
			# using the PcapFile object is going to be more useful.
			def file_to_array(args={})
				filename = args[:filename] || args[:file] || args[:out]
				raise ArgumentError, "Need a :filename in string form to read from." if (filename.nil? || filename.class != String)
				PcapFile.new.file_to_array(args)
			end

			alias_method :f2a, :file_to_array

		end

	end

end

module PacketFu

	# Write is largely deprecated. It was current in PacketFu 0.2.0, but isn't all that useful
	# in 0.3.0 and beyond. Expect it to go away completely by version 1.0, as working with
	# PacketFu::PcapFile directly is generally going to be more rewarding.
	class Write

		class << self

			# format_packets: Pretty much totally deprecated.
			def format_packets(args={})
				arr = args[:arr] || args[:array] || []
				ts = args[:ts] || args[:timestamp] || Time.now.to_i
				ts_inc = args[:ts_inc] || args[:timestamp_increment]
				pkts = PcapFile.new.array_to_file(:endian => PacketFu.instance_variable_get(:@byte_order),
																					:arr => arr,
																					:ts => ts,
																					:ts_inc => ts_inc)
				pkts.body
			end

			# array_to_file is a largely deprecated function for writing arrays of pcaps to a file.
			# Use PcapFile#array_to_file instead.
			def array_to_file(args={})
				filename = args[:filename] || args[:file] || args[:out] || :nowrite
				arr = args[:arr] || args[:array] || []
				ts = args[:ts] || args[:timestamp] || args[:time_stamp] || Time.now.to_f
				ts_inc = args[:ts_inc] || args[:timestamp_increment] || args[:time_stamp_increment]
				byte_order = args[:byte_order] || args[:byteorder] || args[:endian] || args[:endianness] || :little
				append = args[:append]
				Read.set_byte_order(byte_order) if [:big, :little].include? byte_order
				pf = PcapFile.new
				pf.array_to_file(:endian => PacketFu.instance_variable_get(:@byte_order),
												 :arr => arr,
												 :ts => ts,
												 :ts_inc => ts_inc)
				if filename && filename != :nowrite
					if append
						pf.append(filename)
					else
						pf.write(filename)
					end
					return [filename,pf.to_s.size,arr.size,ts,ts_inc]
				else
					return [nil,pf.to_s.size,arr.size,ts,ts_inc]
				end

			end

			alias_method :a2f, :array_to_file

			# Shorthand method for appending to a file. Also shouldn't use.
			def append(args={})
				array_to_file(args.merge(:append => true))
			end

		end

	end

end


# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
