
module PacketFu

	# The Read class facilitates reading from libpcap files, which is the native file format
	# for packet capture utilities such as tcpdump, Wireshark, and PacketFu::PcapFile.
	#
	# This class requires PcapRub to be loaded (for now).
	#
	# == Example
	#
	#   pkt_array = PacketFu::Read.f2a(:file => 'pcaps/my_capture.pcap')
	#
	# === file_to_array() Arguments
	#
	#   :filename | :file | :out
	#     The file to read from.
	#
	# == See Also
	#
	# Write, Capture
	class Read
		
		# file_to_array() translates a libpcap file into an array of packets.
		def self.file_to_array(args={})
			filename = args[:filename] || args[:file] || args[:out]

			raise ArgumentError, "Need a :filename in string form to read from." if (filename.nil? || filename.class != String)
			p = Pcap.open_offline(filename) #Using HD's patch instead of parsing it myself.
			pcap_arr = []
			while this_packet = p.next 
				pcap_arr << this_packet
			end
			pcap_arr
		end
		
		# f2a() is equivalent to file_to_array
		def self.f2a(args={})
			self.file_to_array(args)
		end

		# IRB tab-completion hack.
		#--
		# This silliness is so IRB's tab-completion works for my class methods
		# when those methods are called without first instantiating. (I like
		# tab completion a lot). The alias_methods make sure they show up
		# as instance methods, but but when you call them, you're really 
		# calling the class methods. Tricksy!
		def truth
			"You can't handle the truth" ; true
		end
		#:stopdoc:
		alias_method :file_to_array, :truth
		alias_method :f2a, :truth
		#:startdoc:

	end
end