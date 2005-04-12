#!/usr/bin/ruby

require 'Rex/Post/Dir'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Stdapi'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi

###
#
# Dir
# ---
#
# This class implements directory operations against the remote endpoint
#
###
class Dir < Rex::Post::Dir

	class <<self
		attr_accessor :client
	end

	##
	#
	# Constructor
	#
	##

	# Initializes the directory instance
	def initialize(path)
		self.path   = path
		self.client = self.class.client
	end

	##
	#
	# Enumeration
	#
	##

	# Enumerates all of the contents of the directory
	def each(&block)
		client.dir.foreach(self.path, &block)
	end

	# Enumerates all of the files/folders in a given directory.
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

	# Changes the working directory of the remote process.
	def Dir.chdir(path)
		request = Packet.create_request('stdapi_fs_chdir')

		request.add_tlv(TLV_TYPE_DIRECTORY_PATH, path)

		response = client.send_request(request)

		return 0
	end

	# Creates a directory.
	def Dir.mkdir(path)
		request = Packet.create_request('stdapi_fs_mkdir')

		request.add_tlv(TLV_TYPE_DIRECTORY_PATH, path)

		response = client.send_request(request)

		return 0
	end

	# Returns the current working directory of the remote process.
	def Dir.pwd
		request = Packet.create_request('stdapi_fs_getwd')

		response = client.send_request(request)

		return response.get_tlv(TLV_TYPE_DIRECTORY_PATH).value
	end

	# Synonym for pwd
	def Dir.getwd
		pwd
	end

	# Removes the supplied directory if it's empty
	def Dir.delete(path)
		request = Packet.create_request('stdapi_fs_delete_dir')

		request.add_tlv(TLV_TYPE_DIRECTORY_PATH, path)

		response = client.send_request(request)

		return 0
	end

	# Synonyms for delete
	def Dir.rmdir(path)
		delete(path)
	end

	# Synonyms for delete
	def Dir.unlink(path)
		delete(path)
	end

	attr_reader   :path
protected
	attr_accessor :client
	attr_writer   :path

end

end; end; end; end; end
