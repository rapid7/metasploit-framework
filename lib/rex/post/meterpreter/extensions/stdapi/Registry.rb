#!/usr/bin/ruby

require 'Rex/Post/Process'
require 'Rex/Post/Meterpreter/Packet'
require 'Rex/Post/Meterpreter/Client'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Constants'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Stdapi'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/RegistryKey'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/RegistryValue'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi

DELETE_KEY_FLAG_RECURSIVE = (1 << 0)

TLV_TYPE_HKEY       = TLV_META_TYPE_UINT   | 1000
TLV_TYPE_ROOT_KEY   = TLV_TYPE_HKEY
TLV_TYPE_BASE_KEY   = TLV_META_TYPE_STRING | 1001
TLV_TYPE_PERMISSION = TLV_META_TYPE_UINT   | 1002
TLV_TYPE_KEY_NAME   = TLV_META_TYPE_STRING | 1003

TLV_TYPE_VALUE_NAME = TLV_META_TYPE_STRING | 1010
TLV_TYPE_VALUE_TYPE = TLV_META_TYPE_UINT   | 1011
TLV_TYPE_VALUE_DATA = TLV_META_TYPE_RAW    | 1012

class Registry

	class <<self
		attr_accessor :client
	end

	##
	#
	# Registry key interaction
	#
	##

=begin
	open_key(root_key, base_key, perm)

	Opens the supplied registry key relative to the root key with
	the supplied permissions.  Right now this is merely a wrapper around 
	create_key.
=end
	def Registry.open_key(root_key, base_key, perm = KEY_READ)
		return self.create_key(root_key, base_key, perm)
	end

=begin
	create_key(root_key, base_key, perm)

	Creates the supplied registry key or opens it if it already exists.
=end
	def Registry.create_key(root_key, base_key, perm = KEY_READ)
		request = Packet.create_request('stdapi_registry_create_key')
		
		request.add_tlv(TLV_TYPE_ROOT_KEY, root_key)
		request.add_tlv(TLV_TYPE_BASE_KEY, base_key)
		request.add_tlv(TLV_TYPE_PERMISSION, perm)

		response = self.client.send_request(request)

		return RegistryKey.new(self.client, root_key, base_key, perm,
				response.get_tlv(TLV_TYPE_HKEY).value)
	end

=begin
	delete_key(root_key, base_key, recursive)

	Deletes the supplied registry key.
=end
	def Registry.delete_key(root_key, base_key, recursive = true)
		request = Packet.create_request('stdapi_registry_delete_key')
		flags   = 0

		if (recursive)
			flags |= DELETE_KEY_FLAG_RECURSIVE
		end

		request.add_tlv(TLV_TYPE_ROOT_KEY, root_key)
		request.add_tlv(TLV_TYPE_BASE_KEY, base_key)
		request.add_tlv(TLV_TYPE_FLAGS, flags)

		if (self.client.send_request(request) != nil)
			return true
		end

		return false
	end

=begin
	close_key(hkey)

	Closes the supplied registry key.
=end
	def Registry.close_key(hkey)
		request = Packet.create_request('stdapi_registry_close_key')

		request.add_tlv(TLV_TYPE_HKEY, hkey)

		self.client.send_packet(request)

		return true
	end

=begin
	enum_key(hkey)

	Enumerates the supplied registry key returning an array of key names
=end
	def Registry.enum_key(hkey)
		keys    = []
		request = Packet.create_request('stdapi_registry_enum_key')

		request.add_tlv(TLV_TYPE_HKEY, hkey)

		response = self.client.send_request(request)

		# Enumerate through all of the registry keys
		response.each(TLV_TYPE_KEY_NAME) { |key_name|
			keys << key_name.value
		}

		return keys
	end

	##
	#
	# Registry value interaction
	#
	##

=begin
	set_value(hkey, name, type, data)

	Sets the registry value relative to the supplied hkey.
=end
	def Registry.set_value(hkey, name, type, data)
		request = Packet.create_request('stdapi_registry_set_value')

		request.add_tlv(TLV_TYPE_HKEY, hkey)
		request.add_tlv(TLV_TYPE_VALUE_NAME, name)
		request.add_tlv(TLV_TYPE_VALUE_TYPE, type)

		if (type == REG_SZ)
			data << "\x00"
		end

		request.add_tlv(TLV_TYPE_VALUE_DATA, data)

		response = self.client.send_request(request)

		return true
	end

=begin
	query_value(hkey, name)

	Queries the registry value supplied in name and returns an
	initialized RegistryValue instance if a match is found.
=end
	def Registry.query_value(hkey, name)
		request = Packet.create_request('stdapi_registry_query_value')

		request.add_tlv(TLV_TYPE_HKEY, hkey)
		request.add_tlv(TLV_TYPE_VALUE_NAME, name)

		response = self.client.send_request(request)

		data = response.get_tlv(TLV_TYPE_VALUE_DATA).value;
		type = response.get_tlv(TLV_TYPE_VALUE_TYPE).value;

		if (type == REG_SZ)
			data = data[0..-1]
		elsif (type == REG_DWORD)
			data = data.unpack("N")[0]
		end

		return RegistryValue.new(self.client, hkey, name, type, data)
	end

=begin
	delete_value(hkey, name)

	Deletes the registry value supplied in name from the supplied
	registry key.
=end
	def Registry.delete_value(hkey, name)
		request = Packet.create_request('stdapi_registry_delete_value')

		request.add_tlv(TLV_TYPE_HKEY, hkey)
		request.add_tlv(TLV_TYPE_VALUE_NAME, name)

		if (self.client.send_request(request) != nil)
			return true
		end

		return false
	end

=begin
	enum_value(hkey)

	Enumerates all of the values at the supplied hkey including their
	names.  An array of RegistryValue's is returned.
=end
	def Registry.enum_value(hkey)
		request = Packet.create_request('stdapi_registry_enum_value')
		values  = []

		request.add_tlv(TLV_TYPE_HKEY, hkey)

		response = self.client.send_request(request)

		response.each(TLV_TYPE_VALUE_NAME) { |value_name|
			values << RegistryValue.new(self.client, hkey, value_name.value)
		}

		return values
	end

end

end; end; end; end; end
