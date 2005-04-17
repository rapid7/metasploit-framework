#!/usr/bin/ruby

require 'Rex/Post/UI'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi

###
#
# UI
# --
#
# Allows for interacting with the user interface on the remote machine, 
# such as by disabling the keyboard and mouse.
#
# WARNING:
#
# Using keyboard and mouse enabling/disabling features will result in
# a DLL file being written to disk.
#
###
class UI < Rex::Post::UI

	include Rex::Post::Meterpreter::ObjectAliasesContainer

	##
	#
	# Constructor
	#
	##

	# Initialization
	def initialize(client)
		self.client = client
	end

	##
	#
	# Device enabling/disabling
	#
	##

	# Disable keyboard input
	def disable_keyboard
		return enable_keyboard(false)	
	end

	# Enable keyboard input
	def enable_keyboard(enable = true)
		request = Packet.create_request('stdapi_ui_enable_keyboard')

		request.add_tlv(TLV_TYPE_BOOL, enable)

		response = client.send_request(request)

		return true
	end

	# Disable mouse input
	def disable_mouse
		return enable_mouse(false)
	end

	# Enable mouse input
	def enable_mouse(enable = true)
		request = Packet.create_request('stdapi_ui_enable_mouse')

		request.add_tlv(TLV_TYPE_BOOL, enable)

		response = client.send_request(request)

		return true
	end

protected
	attr_accessor :client

end

end; end; end; end; end
