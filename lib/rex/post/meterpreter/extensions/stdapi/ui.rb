#!/usr/bin/ruby

require 'rex/post/ui'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi

###
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

	#
	# Initializes the post-exploitation user-interface manipulation subsystem.
	#
	def initialize(client)
		self.client = client
	end

	##
	#
	# Device enabling/disabling
	#
	##

	#
	# Disable keyboard input on the remote machine.
	#
	def disable_keyboard
		return enable_keyboard(false)	
	end

	#
	# Enable keyboard input on the remote machine.
	#
	def enable_keyboard(enable = true)
		request = Packet.create_request('stdapi_ui_enable_keyboard')

		request.add_tlv(TLV_TYPE_BOOL, enable)

		response = client.send_request(request)

		return true
	end

	#
	# Disable mouse input on the remote machine.
	#
	def disable_mouse
		return enable_mouse(false)
	end

	#
	# Enable mouse input on the remote machine.
	#
	def enable_mouse(enable = true)
		request = Packet.create_request('stdapi_ui_enable_mouse')

		request.add_tlv(TLV_TYPE_BOOL, enable)

		response = client.send_request(request)

		return true
	end

	#
	# Returns the number of seconds the remote machine has been idle
	# from user input.
	#
	def idle_time
		request = Packet.create_request('stdapi_ui_get_idle_time')

		response = client.send_request(request)

		return response.get_tlv_value(TLV_TYPE_IDLE_TIME);
	end

protected
	attr_accessor :client # :nodoc:

end

end; end; end; end; end
