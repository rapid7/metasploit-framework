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

		return raw_to_host_ip_pair(host, raw, type)
	end

	def resolve_hosts(hostnames)
		request = Packet.create_request('stdapi_net_resolve_hosts')

		hostnames.each do |hostname|
			request.add_tlv(TLV_TYPE_HOST_NAME, hostname)
		end

		response = client.send_request(request)

		hosts = []
		raws = []
		types = []
		lengths = []

		# This is probably neater creating a TLV_GROUP?
		response.each(TLV_TYPE_IP) do |raw|
			raws << raw
		end

		response.each(TLV_TYPE_ADDR_TYPE) do |type|
			types << type
		end

		response.each(TLV_TYPE_ADDR_LENGTH) do |length|
			lengths << length
		end

		0.upto(hostnames.length - 1) do |i|
			raw = raws[i]
			type = types[i]
			length = lengths[i]
			host = hostnames[i]

			hosts << raw_to_host_ip_pair(host, raw, type)
		end

		return hosts
	end

	def raw_to_host_ip_pair(host, raw, type)
		if raw.nil? or host.nil?
			return nil
		end

		if raw.value.empty?
			ip = ""
		else
			if type == 2
				ip = Rex::Socket.addr_ntoa(raw.value[0..3])
			else
				ip = Rex::Socket.addr_ntoa(raw.value[0..1])
			end
		end

		result = { :hostname => host, :ip => ip }

		return result
	end

protected

	attr_accessor :client # :nodoc:

end

end; end; end; end; end; end
