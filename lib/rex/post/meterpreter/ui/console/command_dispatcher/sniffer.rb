require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Privilege escalation extension user interface.
#
###
class Console::CommandDispatcher::Sniffer

	Klass = Console::CommandDispatcher::Sniffer

	include Console::CommandDispatcher

	#
	# Initializes an instance of the sniffer command interaction.
	#
	def initialize(shell)
		super
	end

	#
	# List of supported commands.
	#
	def commands
		{
			"sniffer_interfaces" => "List all remote sniffable interfaces",
			"sniffer_start" => "Capture packets on a previously opened interface",
			"sniffer_stop"  => "Stop packet captures on the specified interface",
			"sniffer_stats" => "View statistics of an active capture",
			"sniffer_dump"  => "Retrieve captured packet data",
		}
	end


	def cmd_sniffer_interfaces(*args)
		
		ifaces = client.sniffer.interfaces()

		print_line()

		ifaces.each do |i|
			print_line(sprintf("%d - '%s' ( type:%d mtu:%d usable:%s dhcp:%s wifi:%s )", 
				i['idx'], i['description'],
				i['type'], i['mtu'], i['usable'], i['dhcp'], i['wireless'])
			)
		end
		
		print_line()

		return true
	end
	
	def cmd_sniffer_start(*args)
		intf = args[0].to_i
		if (intf == 0)
			print_error("Usage: sniffer_start [interface-id] [packet-buffer]")
			return
		end
		maxp = args[1].to_i
		maxp = 200000 if maxp == 0
		 
		client.sniffer.capture_start(intf, maxp)
		print_status("Capture started on interface #{intf} (#{maxp} packet buffer)")
		return true
	end
	
	def cmd_sniffer_stop(*args)
	   intf = args[0].to_i
		if (intf == 0)
			print_error("Usage: sniffer_stop [interface-id]")
			return
		end
		
		client.sniffer.capture_stop(intf)
		print_status("Capture stopped on interface #{intf}")
		return true
	end
	
	def cmd_sniffer_stats(*args)
	   intf = args[0].to_i
		if (intf == 0)
			print_error("Usage: sniffer_stats [interface-id]")
			return
		end
		
		stats = client.sniffer.capture_stats(intf)
		print_status("Capture statistics for interface #{intf}")
		stats.each_key do |k|
			puts "\t#{k}: #{stats[k]}"
		end
		
		return true		
	end
	
	def cmd_sniffer_dump(*args)
	   intf = args[0].to_i
		if (intf == 0 or not args[1])
			print_error("Usage: sniffer_dump [interface-id] [pcap-file]")
			return
		end
		
		fd = nil
		if(::File.exist?(args[1]) and ::File.size(args[1]) >= 24)
			fd = ::File.new(args[1], 'ab+')
		else
			fd = ::File.new(args[1], 'wb+')
			fd.write([0xa1b2c3d4, 2, 4, 0, 0, 65536, 1].pack('NnnNNNN'))
		end
		
		print_status("Dumping packets from interface #{intf}...")
		
		res = client.sniffer.capture_dump(intf)
		res[:packets].each do |pkt|
			fd.write([pkt[:time].to_i, pkt[:time].usec, pkt[:data].length, pkt[:data].length].pack('NNNN') + pkt[:data])
		end
		
		# print_status("#{pkt[:id]} - #{pkt[:time].to_s} - #{pkt[:data].length}")
		
		print_status("Wrote #{res[:packet_count]} packets to PCAP file #{args[1]}")
		fd.close
		
		return true		
	end	
	
	#
	# Name for this dispatcher
	# sni
	def name
		"Sniffer"
	end

end

end
end
end
end
