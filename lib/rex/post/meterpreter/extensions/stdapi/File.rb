#!/usr/bin/ruby

require 'Rex/Post/File'
require 'Rex/Post/Meterpreter/Channel'
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

	def initialize(name, mode = "r", perms = 0)
		self.client = self.class.client
		self.filed  = _open(name, mode, perms)
	end

	def _open(name, mode = "r", perms = 0)
		return Channel.create(self.client, 'stdapi_fs_file', 
				CHANNEL_FLAG_SYNCHRONOUS, [
					{ 'type' => TLV_TYPE_FILE_PATH, 'value' => name       },
					{ 'type' => TLV_TYPE_FILE_MODE, 'value' => mode + "b" },
				])
	end

	protected
	attr_accessor :client

end

end; end; end; end; end
