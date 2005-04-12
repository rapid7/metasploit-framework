#!/usr/bin/ruby

require 'Rex/Post/File'
require 'Rex/Post/Meterpreter/Channel'
require 'Rex/Post/Meterpreter/Channels/Pools/File'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Stdapi'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/IO'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/FileStat'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi

class File < Rex::Post::Meterpreter::Extensions::Stdapi::IO

	include Rex::Post::File
	
	class <<self
		attr_accessor :client
	end

	def File.stat(name)
		return client.filestat.new(name)
	end

	##
	#
	# Constructor
	#
	##

	# Initializes and opens the specified file with the specified permissions
	def initialize(name, mode = "r", perms = 0)
		self.client = self.class.client
		self.filed  = _open(name, mode, perms)
	end

	##
	#
	# IO implementators
	#
	##
	
	# Returns the current position of the file pointer
	def pos
		return self.filed.tell
	end

	# Synonym for sysseek
	def seek(offset, whence = SEEK_SET)
		return self.sysseek(offset, whence)
	end

	# Reads, at most, the supplied number of bytes from the file
	def sysread(length)
		return self.filed.read(length)
	end

	# Seeks to the supplied offset based on the supplied relativity
	def sysseek(offset, whence = SEEK_SET)
		return self.filed.seek(offset, whence)
	end

	# Writes the supplied buffer to the file
	def syswrite(buf)
		return self.filed.write(buf)
	end

	# Closes the file descriptor
	def close
		return self.filed.close
	end

protected

	##
	#
	# Internal methods
	#
	##

	# Creates a File channel using the supplied information
	def _open(name, mode = "r", perms = 0)
		return Channel.create(self.client, 'stdapi_fs_file', 
				Rex::Post::Meterpreter::Channels::Pools::File,
				CHANNEL_FLAG_SYNCHRONOUS, 
				[
					{ 'type' => TLV_TYPE_FILE_PATH, 'value' => name       },
					{ 'type' => TLV_TYPE_FILE_MODE, 'value' => mode + "b" },
				])
	end

	attr_accessor :client

end

end; end; end; end; end
