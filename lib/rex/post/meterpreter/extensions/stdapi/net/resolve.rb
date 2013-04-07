#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/stdapi/tlv'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Net

###
#
# This class provides an interface to the network configuration
# that exists on the remote machine, such as interfaces, and
# routes.
#
###
class Resolve

	##
	#
	# Constructor
	#
	##

	#
	# Initializes a Resolve instance that is used to resolve network addresses
	# on the remote machine.
	#
	def initialize(client)
		self.client = client
	end
	
	def resolve_host(hostname)
                request = Packet.create_request('stdapi_net_resolve_host')
                request.add_tlv(TLV_TYPE_HOST_NAME, hostname)

                response = client.send_request(request)

		type = response.get_tlv_value(TLV_TYPE_ADDR_TYPE)
		length = response.get_tlv_value(TLV_TYPE_ADDR_LENGTH)
		raw = response.get_tlv_value(TLV_TYPE_IP)
		
		if type == 2
			ip = Rex::Socket.addr_ntoa(raw[0..3])
		else
			ip = Rex::Socket.addr_ntoa(raw[0..15])
		end

                return {:hostname => hostname, :ip => ip }
	end

	def resolve_hosts(hostnames)
                request = Packet.create_request('stdapi_net_resolve_hosts')
		
		hostnames.each do |hostname|
                	request.add_tlv(TLV_TYPE_HOST_NAME, hostname)
		end
	
                response = client.send_request(request)
	
		hosts = []
		count = 0
		response.each(TLV_TYPE_IP) do |raw|
			if raw.value.empty?
				ip = ""
			else
				ip = Rex:: Socket.addr_ntoa(raw.value[0..3])
			end
	
			host = { 
					:hostname => hostnames[count],
					:ip => ip
				}
			hosts << host
			count += 1
		end
		
		return hosts
	end
		

	def hostname_to_ipv4(hostname)
		request = Packet.create_request('stdapi_net_resolve_host_ipv4')
		request.add_tlv(TLV_TYPE_HOST_NAME, hostname)
		
		response = client.send_request(request)
		

		return response
	end

	def hostnames_to_ipv4(hostnames)
		request = Packet.create_request('stdapi_net_resolve_hosts_ipv4')
		tlvs = []
		hostnames.each do |hostname|
			tlvs << Tlv(TLV_TYPE_HOST_NAME, hostname)
		end
		request.add_tlvs(tlvs)

		response = client.send_request(request)

		return response
	end

protected

	attr_accessor :client # :nodoc:

end

end; end; end; end; end; end
