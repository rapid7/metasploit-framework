#!/usr/bin/ruby

require 'Rex/Post/Meterpreter/Extensions/Stdapi/Constants'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Sys/Registry'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Sys
module RegistrySubsystem

###
#
# RegistryValue
# -----------
#
# Class wrapper around a logical registry value on the remote side
#
###
class RegistryValue
	def initialize(client, hkey, name, type = nil, data = nil)
		self.client = client
		self.hkey   = hkey
		self.name   = name
		self.type   = type
		self.data   = data
	end	

	# Sets the value's data.
	def set(data, type = nil)
		if (type == nil)
			type = self.type
		end
		if (self.client.sys.registry.set_value(self.hkey, self.name,
				type, data))
			self.data = data
			self.type = type

			return true
		end

		return false
	end

	# Queries the value's data.
	def query()
		val =  self.client.sys.registry.query_value(self.hkey, self.name)

		if (val != nil)
			self.data = val.data
			self.type = val.type
		end

		return self.data
	end

	# Deletes the value.
	def delete()
		return self.client.sys.registry.delete_value(self.hkey, self.name)
	end

	attr_reader   :hkey, :name, :type, :data
protected
	attr_accessor :client
	attr_writer   :hkey, :name, :type, :data
end

end; end; end; end; end; end; end
