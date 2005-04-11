#!/usr/bin/ruby

require 'Rex/Post/Dir'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Stdapi'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi

class Dir < Rex::Post::Dir

	class <<self
		attr_accessor :client
	end

	def initialize(path)
		self.path   = path
		self.client = self.class.client
	end

	def each(&block)
		client.dir.foreach(self.path, &block)
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

=begin
	chdir(path)

	Changes the working directory of the remote process.
=end
	def Dir.chdir(path)
		request = Packet.create_request('stdapi_fs_chdir')

		request.add_tlv(TLV_TYPE_DIRECTORY_PATH, path)

		response = client.send_request(request)

		return 0
	end

=begin
	pwd

	Returns the current working directory of the remote process.
=end
	def Dir.pwd
		request = Packet.create_request('stdapi_fs_getwd')

		response = client.send_request(request)

		return response.get_tlv(TLV_TYPE_DIRECTORY_PATH).value
	end

=begin
	Synonym for pwd
=end
	def Dir.getwd
		pwd
	end

=begin
	delete

	Removes the supplied directory if it's empty
=end
	def Dir.delete(path)
		request = Packet.create_request('stdapi_fs_delete_dir')

		request.add_tlv(TLV_TYPE_DIRECTORY_PATH, path)

		response = client.send_request(request)

		return 0
	end

=begin
	rmdir, unlink

	Synonyms for delete
=end
	def Dir.rmdir(path)
		delete(path)
	end

	def Dir.unlink(path)
		delete(path)
	end

	attr_reader   :path
protected
	attr_accessor :client
	attr_writer   :path


end

end; end; end; end; end
