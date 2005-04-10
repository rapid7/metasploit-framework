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

=begin
	each_key(&block)

	Enumerates all of the child keys within this registry key.
=end
	def each_key(&block)
		return enum_key.each(&block)
	end

=begin
	each_value(&block)

	Enumerates all of the child values within this registry key.
=end
	def each_value(&block)
		return enum_value.each(&block)
	end

=begin
	enum_key()

	Retrieves all of the registry keys that are direct descendents of
	the class' registry key.
=end
	def enum_key()
		return self.client.registry.enum_key(self.hkey)
	end

=begin
	enum_value

	Retrieves all of the registry values that exist within the opened 
	registry key.
=end
	def enum_value()
		return self.client.registry.enum_value(self.hkey)
	end


	##
	#
	# Registry key interaction
	#
	##

=begin
	open_key(base_key, perm)

	Opens a registry key that is relative to this registry key.
=end
	def open_key(base_key, perm = KEY_READ)
		return self.client.registry.open_key(self.hkey, base_key, perm)
	end

=begin
	create_key(base_key, perm)

	Creates a registry key that is relative to this registry key.
=end
	def create_key(base_key, perm = KEY_READ)
		return self.client.registry.create_key(self.hkey, base_key, perm)
	end

=begin
	close()

	Closes the open key.  This must be called if the registry
	key was opened.
=end
	def close()
		if (self.hkey != nil)
			return self.client.registry.close_key(hkey)			
		end

		return false
	end

	##
	#
	# Registry value interaction
	#
	##

=begin
	set_value(name, type, data)

	Sets a value relative to the opened registry key.
=end
	def set_value(name, type, data)
		return self.client.registry.set_value(self.hkey, name, type, data)
	end

=begin
	query_value(name)

	Queries the attributes of the supplied registry value relative to
	the opened registry key.
=end
	def query_value(name)
		return self.client.registry.query_value(self.hkey, name)
	end

	##
	#
	# Serializers
	#
	##

	def to_s
		return self.root_key.to_s + "\\" + self.base_key
	end

	attr_reader   :hkey, :root_key, :base_key, :perm

protected

	attr_accessor :client
	attr_writer   :hkey, :root_key, :base_key, :perm
end

end; end; end; end; end
