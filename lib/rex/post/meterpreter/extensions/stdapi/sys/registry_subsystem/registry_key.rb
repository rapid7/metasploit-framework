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
# RegistryKey
# -----------
#
# Class wrapper around a logical registry key on the remote side
#
###
class RegistryKey
	def initialize(client, root_key, base_key, perm, hkey)
		self.client   = client
		self.root_key = root_key
		self.base_key = base_key
		self.perm     = perm
		self.hkey     = hkey
	end

	##
	#
	# Enumerators
	#
	##

	# Enumerates all of the child keys within this registry key.
	def each_key(&block)
		return enum_key.each(&block)
	end

	# Enumerates all of the child values within this registry key.
	def each_value(&block)
		return enum_value.each(&block)
	end

	# Retrieves all of the registry keys that are direct descendents of
	# the class' registry key.
	def enum_key()
		return self.client.sys.registry.enum_key(self.hkey)
	end

	# Retrieves all of the registry values that exist within the opened 
	# registry key.
	def enum_value()
		return self.client.sys.registry.enum_value(self.hkey)
	end


	##
	#
	# Registry key interaction
	#
	##

	# Opens a registry key that is relative to this registry key.
	def open_key(base_key, perm = KEY_READ)
		return self.client.sys.registry.open_key(self.hkey, base_key, perm)
	end

	# Creates a registry key that is relative to this registry key.
	def create_key(base_key, perm = KEY_READ)
		return self.client.sys.registry.create_key(self.hkey, base_key, perm)
	end

	# Deletes a registry key that is relative to this registry key.
	def delete_key(base_key, recursive = true)
		return self.client.sys.registry.delete_key(self.hkey, base_key, recursive)
	end

	# Closes the open key.  This must be called if the registry
	# key was opened.
	def close()
		if (self.hkey != nil)
			return self.client.sys.registry.close_key(hkey)			
		end

		return false
	end

	##
	#
	# Registry value interaction
	#
	##

	# Sets a value relative to the opened registry key.
	def set_value(name, type, data)
		return self.client.sys.registry.set_value(self.hkey, name, type, data)
	end

	# Queries the attributes of the supplied registry value relative to
	# the opened registry key.
	def query_value(name)
		return self.client.sys.registry.query_value(self.hkey, name)
	end

	##
	#
	# Serializers
	#
	##

	# Returns the path to the key
	def to_s
		return self.root_key.to_s + "\\" + self.base_key
	end

	attr_reader   :hkey, :root_key, :base_key, :perm

protected

	attr_accessor :client
	attr_writer   :hkey, :root_key, :base_key, :perm
end

end; end; end; end; end; end; end
