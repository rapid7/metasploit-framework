#!/usr/bin/ruby

require 'Rex/Post/Meterpreter/Extension'
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

# Process
TLV_TYPE_PID            = TLV_META_TYPE_UINT    |    0

# Registry
TLV_TYPE_HKEY           = TLV_META_TYPE_UINT    | 1000
TLV_TYPE_ROOT_KEY       = TLV_TYPE_HKEY
TLV_TYPE_BASE_KEY       = TLV_META_TYPE_STRING  | 1001
TLV_TYPE_PERMISSION     = TLV_META_TYPE_UINT    | 1002
TLV_TYPE_KEY_NAME       = TLV_META_TYPE_STRING  | 1003
TLV_TYPE_VALUE_NAME     = TLV_META_TYPE_STRING  | 1010
TLV_TYPE_VALUE_TYPE     = TLV_META_TYPE_UINT    | 1011
TLV_TYPE_VALUE_DATA     = TLV_META_TYPE_RAW     | 1012

# Fs
TLV_TYPE_DIRECTORY_PATH = TLV_META_TYPE_STRING  | 1200
TLV_TYPE_FILE_NAME      = TLV_META_TYPE_STRING  | 1201
TLV_TYPE_FILE_PATH      = TLV_META_TYPE_STRING  | 1202
TLV_TYPE_FILE_MODE      = TLV_META_TYPE_STRING  | 1203
TLV_TYPE_STAT_BUF       = TLV_META_TYPE_COMPLEX | 1220

DELETE_KEY_FLAG_RECURSIVE = (1 << 0)

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
