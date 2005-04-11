#!/usr/bin/ruby

require 'Rex/Post/Dir'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Stdapi'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi

TLV_TYPE_DIRECTORY_PATH = TLV_META_TYPE_STRING | 1200
TLV_TYPE_FILE_NAME      = TLV_META_TYPE_STRING | 1201
TLV_TYPE_FILE_PATH      = TLV_META_TYPE_STRING | 1202

class Dir < Rex::Post::Dir

	class <<self
		attr_accessor :client
	end

=begin
	entries(name)

	Enumerates all of the files/folders in a given directory.
=end
	def Dir.entries(name)
		request = Packet.create_request('stdapi_fs_ls')
		files   = []

		request.add_tlv(TLV_TYPE_DIRECTORY_PATH, name)

		response = client.send_request(request)

		response.each(TLV_TYPE_FILE_NAME) { |file_name|
			files << file_name.value
		}
		
		return files
	end

end

end; end; end; end; end
