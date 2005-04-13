#!/usr/bin/ruby

require 'Rex/Post/Meterpreter/Extension'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Tlv'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Dir'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/File'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/FileStat'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Process'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Registry'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi

###
#
# Stdapi
# ------
#
# Standard ruby interface to remote entities
#
###
class Stdapi < Extension
	def initialize(client)
		super(client, 'stdapi')

		# Alias the following things on the client object so that they
		# can be directly referenced
		client.register_extension_alias('dir', self.dir)
		client.register_extension_alias('file', self.file)
		client.register_extension_alias('filestat', self.filestat)
		client.register_extension_alias('process', self.process)
		client.register_extension_alias('registry', self.registry)
	end

	# Sets the client instance on a duplicated copy of the supplied class
	def brand(klass)
		klass = klass.dup
		klass.client = self.client
		return klass
	end

	# Returns a copy of the Dir class
	def dir
		brand(Rex::Post::Meterpreter::Extensions::Stdapi::Dir)
	end

	# Returns a copy of the File class
	def file
		brand(Rex::Post::Meterpreter::Extensions::Stdapi::File)
	end

	# Returns a copy of the FileStat class
	def filestat
		brand(Rex::Post::Meterpreter::Extensions::Stdapi::FileStat)
	end

	# Returns a copy of the Process class
	def process
		brand(Rex::Post::Meterpreter::Extensions::Stdapi::Process)
	end

	# Returns a copy of the Registry class
	def registry
		brand(Rex::Post::Meterpreter::Extensions::Stdapi::Registry)
	end
end

end; end; end; end; end
