
module PacketFu
	
	# The Write class facilitates writing to libpcap files, which is the native file format
	# for packet capture utilities such as tcpdump, Wireshark, and PacketFu::PcapFile.
	#
	# == Example
	#
	#   cap = PacketFu::Capture.new(:start => true)
	#   sleep 10
	#   cap.save
	#   pkt_array = cap.array
	#   PacketFu::Write.a2f(:file => 'pcaps/my_capture.pcap', :array => pkt_array)
	#
	# === array_to_file() Arguments
	#
	#   :filename | :file | :out
	#     The file to write to. If it exists, it will be overwritten. By default, no file will be written.
	#
	#   :array | arr
	#     The array to read packet data from. Note, these should be strings, and not packet objects!
	#
	#   :ts | :timestamp
	#     The starting timestamp. By default, it is the result of Time.now.to_i
	#
	#   :ts_inc | :timestamp_increment
	#     The timestamp increment, in seconds. (Sorry, no usecs yet)
	#
	# == See Also
	#
	# Read, Capture
	class Write
		
		# Writes an array of binary data to a libpcap file.
		def self.array_to_file(args={}) 
			filename = args[:filename] || args[:file] || args[:out] || :nowrite
			arr = args[:arr] || args[:array] || []
			ts = args[:ts] || args[:timestamp] || Time.now.to_i
			ts_inc = args[:ts_inc] || args[:timestamp_increment] || 1

			if arr.class != Array
				raise ArgumentError, "This needs to be an array."
			end
			
			formatted_packets = []
			arr.each do |pkt|
				this_pkt = PcapPacket.new
				this_pkt.data = pkt[0,0xffff]
				this_pkt.orig_len = pkt.size # orig_len isn't calc'ed already.
				this_pkt.ts_sec = ts += decimal_to_usecs(ts_inc)[0]
				formatted_packets << this_pkt.to_s
			end
			filedata = PcapFile.new
			filedata.read(PcapFile.new.to_s + formatted_packets.join) # Like a cat playing the bass.

			if filename != :nowrite
				out = File.new(filename.to_s, 'w')
				out.print filedata
				out.close
				# Return [filename, file size, # of packets, initial timestamp, timestamp increment]
				ret = [filename,filedata.to_s.size,arr.size,ts,ts_inc]
			else
				ret = [nil,filedata.to_s.size,arr.size,ts,ts_inc]
			end
			
		end
		def self.append(args={})
			file = args[:file] || args[:out] || :nowrite
			pkt  = args[:packet] || args[:pkt] || nil
			ts   = args[:ts] || args[:timestamp] || Time.now.to_i
			if (file == :nowrite)
				return false
			end
			if (!file.kind_of?(File)) 
				file = File.new(file, "a")
			end

			pc_pkt = PcapPacket.new
			pc_pkt.data = pkt.to_s[0,0xffff]
			pc_pkt.orig_len = pkt.size
			pc_pkt.ts_sec = decimal_to_usecs(ts)[0]
			file.print(pc_pkt.to_s)

			return pc_pkt.to_s.size
		end


		# A synonym for array_to_file()
		def self.a2f(args={})
			self.array_to_file(args)
		end

		# TODO: Wire this in later to enable incrementing by microseconds.
		def self.decimal_to_usecs(decimal)
			secs = decimal.to_i
			usecs = decimal.to_f.to_s.split('.')[1]
			[secs,usecs]
		end

		# IRB tab-completion hack.
		def truth
			"Stranger than fiction" ; true
		end
		#:stopdoc:
		alias_method :array_to_file, :truth
		alias_method :a2f, :truth
		#:startdoc:

	end
end
