module PacketFu


	# PcapHeader describes the libpcap file header format, and is used in PcapFile.
	class PcapHeader < BinData::MultiValue
		string				:magic,			:length => 4, :initial_value => "\xd4\xc3\xb2\xa1"
		uint16le			:ver_major,	:initial_value =>	2 
		uint16le			:ver_minor,	:initial_value => 4
		int32le				:thiszone,	:initial_value => 0
		uint32le			:sigfigs,		:initial_value => 0
		uint32le			:snaplen,		:initial_value => 0xffff
		uint32le			:network,		:initial_value => 1
	end

	# PcapPacket describes a complete libpcap-formatted packet, which includes timestamp
	# and length information. It is used in PcapPackets class.
	class PcapPacket < BinData::MultiValue
		uint32le	:ts_sec
		uint32le	:ts_usec
		uint32le	:incl_len,	:value => lambda {data.length}
		uint32le	:orig_len	
		string		:data,		:read_length => :incl_len
	end

	# PcapPackets is an BinData array type, used to collect packets and their associated
	# frame data. It is part of the PcapFile class.
	class PcapPackets < BinData::MultiValue
		array 		:data, :type => :pcap_packet, :read_until => :eof
	end

	# PcapFile is a complete libpcap file struct, made up of a PcapHeader and PcapPackets.
	#
	# See http://wiki.wireshark.org/Development/LibpcapFileFormat
	class PcapFile < BinData::MultiValue
		pcap_header			:head
		pcap_packets		:body
	end
end