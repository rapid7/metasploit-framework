#!/usr/bin/ruby

require 'Rex/Post/File'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Stdapi'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi

class File 

	include Rex::Post::File
	
	class <<self
		attr_accessor :client
	end

	def initialize(name, mode = "r", perms = 0)
		self.client = self.class.client
	end

	def File.stat(name)
		return client.filestat.new(name)
	end

	protected
	attr_accessor :client

end

end; end; end; end; end
