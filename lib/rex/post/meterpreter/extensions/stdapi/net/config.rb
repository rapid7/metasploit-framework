#!/usr/bin/env ruby

require 'rex/post/meterpreter/extensions/stdapi/tlv'
require 'rex/post/meterpreter/extensions/stdapi/net/route'
require 'rex/post/meterpreter/extensions/stdapi/net/interface'

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
class Config

	##
	#
	# Constructor
	#
	##

	#
	# Initializes a Config instance that is used to get information about the
	# network configuration of the remote machine.
	#
	def initialize(client)
		self.client = client
	end

	##
	#
	# Interfaces
	#
	##

	#
	# Enumerates each interface.
	#
	def each_interface(&block)
		get_interfaces().each(&block)
	end

	#
	# Returns an array of network interfaces with each element.
	#
	# being an Interface
	def get_interfaces
		request = Packet.create_request('stdapi_net_config_get_interfaces')
		ifaces  = []

		response = client.send_request(request)

		response.each(TLV_TYPE_NETWORK_INTERFACE) { |iface|
			ifaces << Interface.new(
					iface.get_tlv_value(TLV_TYPE_IP),
					iface.get_tlv_value(TLV_TYPE_NETMASK),
					iface.get_tlv_value(TLV_TYPE_MAC_ADDRESS),
					iface.get_tlv_value(TLV_TYPE_MAC_NAME))
		}

		return ifaces
	end

	alias interfaces get_interfaces

	##
	#
	# Routing
	#
	##

	#
	# Enumerates each route.
	#
	def each_route(&block)
		get_routes().each(&block)
	end

	#
	# Returns an array of routes with each element being a Route.
	#
	def get_routes
		request = Packet.create_request('stdapi_net_config_get_routes')
		routes  = []

		response = client.send_request(request)

		# Build out the array of routes
		response.each(TLV_TYPE_NETWORK_ROUTE) { |route|
			routes << Route.new(
					route.get_tlv_value(TLV_TYPE_SUBNET),
					route.get_tlv_value(TLV_TYPE_NETMASK),
					route.get_tlv_value(TLV_TYPE_GATEWAY))
		}

		return routes
	end
	
	alias routes get_routes

	#
	# Adds a route to the target machine.
	# 
	def add_route(subnet, netmask, gateway)
		request = Packet.create_request('stdapi_net_config_add_route')

		request.add_tlv(TLV_TYPE_SUBNET_STRING, subnet)
		request.add_tlv(TLV_TYPE_NETMASK_STRING, netmask)
		request.add_tlv(TLV_TYPE_GATEWAY_STRING, gateway)

		response = client.send_request(request)

		return true
	end

	#
	# Removes a route from the target machine.
	#
	def remove_route(subnet, netmask, gateway)
		request = Packet.create_request('stdapi_net_config_remove_route')

		request.add_tlv(TLV_TYPE_SUBNET_STRING, subnet)
		request.add_tlv(TLV_TYPE_NETMASK_STRING, netmask)
		request.add_tlv(TLV_TYPE_GATEWAY_STRING, gateway)

		response = client.send_request(request)

		return true
	end

protected
	
	attr_accessor :client # :nodoc:

end

end; end; end; end; end; end