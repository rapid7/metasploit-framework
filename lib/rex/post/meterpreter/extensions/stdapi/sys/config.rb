#!/usr/bin/env ruby

require 'rex/post/process'
require 'rex/post/meterpreter/packet'
require 'rex/post/meterpreter/client'
require 'rex/post/meterpreter/extensions/stdapi/constants'
require 'rex/post/meterpreter/extensions/stdapi/stdapi'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Sys

###
#
# This class provides access to remote system configuration and information.
#
###
class Config

	def initialize(client)
		self.client = client
	end

	#
	# Returns the username that the remote side is running as.
	#
	def getuid
		request  = Packet.create_request('stdapi_sys_config_getuid')
		response = client.send_request(request)
		return response.get_tlv_value(TLV_TYPE_USER_NAME)
	end

	#
	# Returns a hash of information about the remote computer.
	#
	def sysinfo
		request  = Packet.create_request('stdapi_sys_config_sysinfo')
		response = client.send_request(request)

		{
			'Computer' => response.get_tlv_value(TLV_TYPE_COMPUTER_NAME),
			'OS'       => response.get_tlv_value(TLV_TYPE_OS_NAME),
		}
	end

	#
	# Calls RevertToSelf on the remote machine.
	#
	def revert_to_self
		client.send_request(
			Packet.create_request('stdapi_sys_config_rev2self'))
	end

protected

	attr_accessor :client

end

end; end; end; end; end; end