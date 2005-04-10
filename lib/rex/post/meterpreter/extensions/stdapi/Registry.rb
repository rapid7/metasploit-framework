#!/usr/bin/ruby

require 'Rex/Post/Process'
require 'Rex/Post/Meterpreter/Packet'
require 'Rex/Post/Meterpreter/Client'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Constants'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Stdapi'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi

TLV_TYPE_HKEY       = TLV_META_TYPE_UINT   | 1000
TLV_TYPE_ROOT_KEY   = TLV_TYPE_HKEY
TLV_TYPE_BASE_KEY   = TLV_META_TYPE_STRING | 1001
TLV_TYPE_PERMISSION = TLV_META_TYPE_UINT   | 1002


class Registry

	class <<self
		attr_accessor :client
	end

	def Registry.open_key(root_key, base_key, perm = KEY_READ)
		request = Packet.create_request('stdapi_registry_open_key')

		request.add_tlv(TLV_TYPE_ROOT_KEY, root_key)
		request.add_tlv(TLV_TYPE_BASE_KEY, base_key)
		request.add_tlv(TLV_TYPE_PERMISSION, perm)

		response = self.client.send_request(request)

		return response.get_tlv(TLV_TYPE_HKEY).value
	end

end

end; end; end; end; end
