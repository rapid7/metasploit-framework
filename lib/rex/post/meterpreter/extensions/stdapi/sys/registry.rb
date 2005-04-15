#!/usr/bin/ruby

require 'Rex/Post/Process'
require 'Rex/Post/Meterpreter/Packet'
require 'Rex/Post/Meterpreter/Client'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Constants'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Stdapi'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Sys/RegistrySubsystem/RegistryKey'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Sys/RegistrySubsystem/RegistryValue'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Sys

###
#
# Registry
# --------
#
# This class provides access to the Windows registry on the remote 
# machine.
#
###
class Registry

	class <<self
		attr_accessor :client
	end

	##
	#
	# Registry key interaction
	#
	##

	# Opens the supplied registry key relative to the root key with
	# the supplied permissions.  Right now this is merely a wrapper around 
	# create_key.
	def Registry.open_key(root_key, base_key, perm = KEY_READ)
		return self.create_key(root_key, base_key, perm)
	end

	# Creates the supplied registry key or opens it if it already exists.
	def Registry.create_key(root_key, base_key, perm = KEY_READ)
		request = Packet.create_request('stdapi_registry_create_key')
		
		request.add_tlv(TLV_TYPE_ROOT_KEY, root_key)
		request.add_tlv(TLV_TYPE_BASE_KEY, base_key)
		request.add_tlv(TLV_TYPE_PERMISSION, perm)

		response = client.send_request(request)

		return Rex::Post::Meterpreter::Extensions::Stdapi::Sys::RegistrySubsystem::RegistryKey.new(
				client, root_key, base_key, perm, response.get_tlv(TLV_TYPE_HKEY).value)
	end

	# Deletes the supplied registry key.
	def Registry.delete_key(root_key, base_key, recursive = true)
		request = Packet.create_request('stdapi_registry_delete_key')
		flags   = 0

		if (recursive)
			flags |= DELETE_KEY_FLAG_RECURSIVE
		end

		request.add_tlv(TLV_TYPE_ROOT_KEY, root_key)
		request.add_tlv(TLV_TYPE_BASE_KEY, base_key)
		request.add_tlv(TLV_TYPE_FLAGS, flags)

		if (client.send_request(request) != nil)
			return true
		end

		return false
	end

	# Closes the supplied registry key.
	def Registry.close_key(hkey)
		request = Packet.create_request('stdapi_registry_close_key')

		request.add_tlv(TLV_TYPE_HKEY, hkey)

		client.send_packet(request)

		return true
	end

	# Enumerates the supplied registry key returning an array of key names
	def Registry.enum_key(hkey)
		keys    = []
		request = Packet.create_request('stdapi_registry_enum_key')

		request.add_tlv(TLV_TYPE_HKEY, hkey)

		response = client.send_request(request)

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

	# Sets the registry value relative to the supplied hkey.
	def Registry.set_value(hkey, name, type, data)
		request = Packet.create_request('stdapi_registry_set_value')

		request.add_tlv(TLV_TYPE_HKEY, hkey)
		request.add_tlv(TLV_TYPE_VALUE_NAME, name)
		request.add_tlv(TLV_TYPE_VALUE_TYPE, type)

		if (type == REG_SZ)
			data << "\x00"
		else (type == REG_DWORD)
			data = [ data.to_i ].pack("V")
		end

		request.add_tlv(TLV_TYPE_VALUE_DATA, data)

		response = client.send_request(request)

		return true
	end

	# Queries the registry value supplied in name and returns an
	# initialized RegistryValue instance if a match is found.
	def Registry.query_value(hkey, name)
		request = Packet.create_request('stdapi_registry_query_value')

		request.add_tlv(TLV_TYPE_HKEY, hkey)
		request.add_tlv(TLV_TYPE_VALUE_NAME, name)

		response = client.send_request(request)

		data = response.get_tlv(TLV_TYPE_VALUE_DATA).value;
		type = response.get_tlv(TLV_TYPE_VALUE_TYPE).value;

		if (type == REG_SZ)
			data = data[0..-1]
		elsif (type == REG_DWORD)
			data = data.unpack("N")[0]
		end

		return Rex::Post::Meterpreter::Extensions::Stdapi::Sys::RegistrySubsystem::RegistryValue.new(
				client, hkey, name, type, data)
	end

	# Deletes the registry value supplied in name from the supplied
	# registry key.
	def Registry.delete_value(hkey, name)
		request = Packet.create_request('stdapi_registry_delete_value')

		request.add_tlv(TLV_TYPE_HKEY, hkey)
		request.add_tlv(TLV_TYPE_VALUE_NAME, name)

		if (client.send_request(request) != nil)
			return true
		end

		return false
	end

	# Enumerates all of the values at the supplied hkey including their
	# names.  An array of RegistryValue's is returned.
	def Registry.enum_value(hkey)
		request = Packet.create_request('stdapi_registry_enum_value')
		values  = []

		request.add_tlv(TLV_TYPE_HKEY, hkey)

		response = client.send_request(request)

		response.each(TLV_TYPE_VALUE_NAME) { |value_name|
			values << Rex::Post::Meterpreter::Extensions::Stdapi::Sys::RegistrySubsystem::RegistryValue.new(
					client, hkey, value_name.value)
		}

		return values
	end

end

end; end; end; end; end; end
