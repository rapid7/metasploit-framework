#!/usr/bin/ruby

require 'Rex/Post/Meterpreter/Extensions/Stdapi/Constants'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Registry'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi

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

=begin
	set(data, type)

	Sets the value's data.
=end
	def set(data, type = nil)
		if (type == nil)
			type = self.type
		end
		if (self.client.registry.set_value(self.hkey, self.name,
				type, data))
			self.data = data
			self.type = type

			return true
		end

		return false
	end

=begin
	query()

	Queries the value's data.
=end
	def query()
		val =  self.client.registry.query_value(self.hkey, self.name)

		if (val != nil)
			self.data = val.data
			self.type = val.type
		end

		return self.data
	end

=begin
	delete()

	Deletes the value.
=end
	def delete()
		return self.client.registry.delete_value(self.hkey, self.name)
	end

	##
	#
	# Attributes
	#
	##

	attr_reader   :hkey, :name, :type, :data
	protected
	attr_accessor :client
	attr_writer   :hkey, :name, :type, :data
end

end; end; end; end; end
