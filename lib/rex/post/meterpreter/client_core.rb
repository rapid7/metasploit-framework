#!/usr/bin/ruby

require 'Rex/Post/Meterpreter/Packet'

module Rex
module Post
module Meterpreter

###
#
# ClientCore
# ----------
#
# This class is responsible for providing the interface to the core
# client-side meterpreter API which facilitates the loading of extensions
# and the interaction with channels.
#
#
###
class ClientCore

	def initialize(client)
		self.client = client
	end

	#
	# Core commands
	#

=begin
	
	load_library

	Loads a library on the remote meterpreter instance.  This method
	supports loading both extension and non-extension libraries and
	also supports loading libraries from memory or disk depending
	on the flags that are specified

	Supported flags:

	LibraryFilePath
		The path to the library that is to be loaded

	TargetFilePath
		The target library path when uploading

	UploadLibrary
		Indicates whether or not the library should be uploaded

	SaveToDisk
		Indicates whether or not the library should be saved to disk
		on the remote machine

	Extension
		Indicates whether or not the library is a meterpreter extension

=end
	def load_library(opts)
		library_path = opts['LibraryFilePath']
		target_path  = opts['TargetFilePath']
		load_flags   = LOAD_LIBRARY_FLAG_LOCAL

		# No library path, no cookie.
		if (library_path == nil)
			raise ArgumentError, "No library file path was supplied", caller
		end

		# Set up the proper loading flags
		if (opts['UploadLibrary'])
			load_flags &= ~LOAD_LIBRARY_FLAG_LOCAL
		end
		if (opts['SaveToDisk'])
			load_flags |= LOAD_LIBRARY_FLAG_ON_DISK
		end
		if (opts['Extension'])
			load_flags |= LOAD_LIBRARY_FLAG_EXTENSION
		end

		# Create a request packet
		request = Packet.create_request('core_loadlib')

		# If we must upload the library, do so now
		if (!(load_flags & LOAD_LIBRARY_FLAG_LOCAL))
			image = IO.readlines(library_path).join

			if (image != nil)
				request.add_tlv(TLV_TYPE_DATA, image)
			else
				raise RuntimeError, "Failed to serialize library #{library_path}.", caller
			end

			# If it's an extension we're dealing with, rename the library
			# path of the local and target so that it gets loaded with a random
			# name
			if (opts['Extension'])
				library_path = "ext" + rand(1000000) + ".dll"
				target_path  = library_path
			end
		end

		# Add the base TLVs
		request.add_tlv(TLV_TYPE_LIBRARY_PATH, library_path)
		request.add_tlv(TLV_TYPE_FLAGS, load_flags)

		if (target_path != nil)
			request.add_tlv(TLV_TYPE_TARGET_PATH, target_path)
		end

		# Transmit the request and wait 30 seconds for a response
		response = self.client.send_packet_wait_response(request, 30)

		# No response?
		if (response == nil)
			raise RuntimeError, "No response was received to the core_loadlib request.", caller
		elsif (response.result != 0)
			raise RuntimeError, "The core_loadlib request failed with result: #{response.result}.", caller
		end

		return true
	end

=begin

	use

	Loads a meterpreter extension on the remote server instance and
	initializes the client-side extension handlers

	Module
		The module that should be loaded
	
	Modules
		The modules that should be loaded

	LoadFromDisk
		Indicates that the library should be loaded from disk, not from
		memory on the remote machine

=end
	def use(opts)
		modules = []

		if (opts['Module'])
			modules << opts['Module']
		elsif (opts['Modules'])
			modules = opts['Modules']
		end

		if (modules.length == 0)
			raise RuntimeError, "No modules were specified", caller
		end

		# Enumerate all of the modules, loading each one
		modules.each { |mod|

			load_library(
					'LibraryFilePath' => 'data/meterpreter/' + mod + '.dll',
					'UploadLibrary'   => true,
					'Extension'       => true,
					'SaveToDisk'      => opts['LoadFromDisk']
				)
			
		}

		return true
	end

	protected
	attr_accessor :client

end

end; end; end
