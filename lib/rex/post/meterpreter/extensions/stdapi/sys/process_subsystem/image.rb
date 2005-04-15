#!/usr/bin/ruby

require 'Rex/Post/Meterpreter/Client'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Constants'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Sys
module ProcessSubsystem

###
#
# Image
# -----
#
# Interacts with loading, unloading, enumerating, and querying
# image files in the context of a given process.
#
###
class Image

	##
	#
	# Constructor
	#
	##

	def initialize(process)
		self.process = process
	end

	# Loads an image file into the context of the process
	def load(image_path)
		request = Packet.create_request('stdapi_sys_process_image_load')

		request.add_tlv(TLV_TYPE_HANDLE, process.handle)
		request.add_tlv(TLV_TYPE_IMAGE_FILE_PATH, image_path)

		response = process.client.send_request(request)

		return response.get_tlv_value(TLV_TYPE_IMAGE_BASE)
	end

	# Returns the address of the procedure that is found in the supplied
	# library
	def get_procedure_address(image_file, procedure)
		request = Packet.create_request('stdapi_sys_process_image_get_proc_address')

		request.add_tlv(TLV_TYPE_IMAGE_FILE, image_file)
		request.add_tlv(TLV_TYPE_PROCEDURE_NAME, procedure)

		response = process.client.send_request(request)

		return response.get_tlv_value(TLV_TYPE_PROCEDURE_ADDRESS)
	end

	# Unloads an image file that is loaded into the address space of the
	# process by its base address
	def unload(base)
		request = Packet.create_request('stdapi_sys_process_image_unload')

		request.add_tlv(TLV_TYPE_HANDLE, process.handle)
		request.add_tlv(TLV_TYPE_IMAGE_BASE, base)

		response = process.client.send_request(request)

		return true
	end

protected
	attr_accessor :process

end

end; end; end; end; end; end; end
