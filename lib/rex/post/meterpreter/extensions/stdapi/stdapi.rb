#!/usr/bin/ruby

require 'Rex/Post/Meterpreter/ObjectAliases'
require 'Rex/Post/Meterpreter/Extension'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Constants'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Tlv'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Fs/Dir'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Fs/File'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Fs/FileStat'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/UI'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Sys/Process'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Sys/Registry'

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
		client.register_extension_aliases(
			[
				{ 
					'name' => 'fs',
					'ext'  => ObjectAliases.new(
						{
							'dir'      => self.dir,
							'file'     => self.file,
							'filestat' => self.filestat
						})
				},
				{
					'name' => 'sys',
					'ext'  => ObjectAliases.new(
						{
							'process'  => self.process,
							'registry' => self.registry
						})
				},
				{
					'name' => 'ui',
					'ext'  => UI.new(client)
				}

			])
	end

	# Sets the client instance on a duplicated copy of the supplied class
	def brand(klass)
		klass = klass.dup
		klass.client = self.client
		return klass
	end

	# Returns a copy of the Dir class
	def dir
		brand(Rex::Post::Meterpreter::Extensions::Stdapi::Fs::Dir)
	end

	# Returns a copy of the File class
	def file
		brand(Rex::Post::Meterpreter::Extensions::Stdapi::Fs::File)
	end

	# Returns a copy of the FileStat class
	def filestat
		brand(Rex::Post::Meterpreter::Extensions::Stdapi::Fs::FileStat)
	end

	# Returns a copy of the Process class
	def process
		brand(Rex::Post::Meterpreter::Extensions::Stdapi::Sys::Process)
	end

	# Returns a copy of the Registry class
	def registry
		brand(Rex::Post::Meterpreter::Extensions::Stdapi::Sys::Registry)
	end
end

end; end; end; end; end
