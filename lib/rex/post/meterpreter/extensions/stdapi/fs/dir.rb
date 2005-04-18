#!/usr/bin/ruby

require 'Rex/Post/Dir'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Stdapi'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Fs

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
		client.fs.dir.foreach(self.path, &block)
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

	##
	#
	# General directory operations
	#
	##

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

	##
	#
	# Directory mirroring
	#
	##

	# Downloads the contents of a remote directory a 
	# local directory, optionally in a recursive fashion.
	def Dir.download(dst, src, recursive = false)
		self.entries(src).each { |src_sub|
			dst_item = dst + ::File::SEPARATOR + src_sub
			src_item = src + File::SEPARATOR + src_sub

			if (src_sub == '.' or src_sub == '..')
				next
			end

			src_stat = client.fs.filestat.new(src_item)

			if (src_stat.file?)
				client.fs.file.download(dst_item, src_item)
			elsif (src_stat.directory?)
				if (recursive == false)
					next
				end

				begin
					::Dir.mkdir(dst_item)
				rescue
				end

				download(dst_item, src_item, recursive)
			end
		}
	end

	# Uploads the contents of a local directory to a remote 
	# directory, optionally in a recursive fashion.
	def Dir.upload(dst, src, recursive = false)
		::Dir.entries(src).each { |src_sub|
			dst_item = dst + File::SEPARATOR + src_sub
			src_item = src + ::File::SEPARATOR + src_sub

			if (src_sub == '.' or src_sub == '..')
				next
			end

			src_stat = ::File.stat(src_item)

			if (src_stat.file?)
				client.fs.file.upload(dst_item, src_item)
			elsif (src_stat.directory?)
				if (recursive == false)
					next
				end

				begin
					self.mkdir(dst_item)
				rescue
				end

				upload(dst_item, src_item, recursive)
			end
		}
	end

	attr_reader   :path
protected
	attr_accessor :client
	attr_writer   :path

end

end; end; end; end; end; end
