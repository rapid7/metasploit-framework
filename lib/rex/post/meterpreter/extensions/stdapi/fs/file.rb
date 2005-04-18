#!/usr/bin/ruby

require 'Rex/Post/File'
require 'Rex/Post/Meterpreter/Channel'
require 'Rex/Post/Meterpreter/Channels/Pools/File'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Stdapi'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Fs/IO'
require 'Rex/Post/Meterpreter/Extensions/Stdapi/Fs/FileStat'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Fs

class File < Rex::Post::Meterpreter::Extensions::Stdapi::Fs::IO

SEPARATOR = "\\"
Separator = "\\"

	include Rex::Post::File
	
	class <<self
		attr_accessor :client
	end

	def File.basename(*a)
		path = a[0]
		sep  = "\\" + File::SEPARATOR

		# I suck at regex.
		path =~ /(.*)#{sep}(.*)$/

		return $2
	end

	# Expands a file path
	def File.expand_path(path)
		request = Packet.create_request('stdapi_fs_file_expand_path')

		request.add_tlv(TLV_TYPE_FILE_PATH, path)

		response = client.send_request(request)
		
		return response.get_tlv_value(TLV_TYPE_FILE_PATH)
	end

	def File.stat(name)
		return client.fs.filestat.new(name)
	end

	# Upload one or more files to the remote computer the remote
	# directory supplied in destination
	def File.upload(destination, *src_files)
		src_files.each { |src|
			dest = destination

			if (File.basename(destination) != ::File.basename(src))
				dest += File::SEPARATOR + ::File.basename(src)
			end

			# Open the file on the remote side for writing and read
			# all of the contents of the local file
			dest_fd = client.fs.file.new(dest, "wb")
			src_buf = ::IO.readlines(src).join

			dest_fd.write(src_buf)
			dest_fd.close
		}
	end

	# Download one or more files from the remote computer to the local 
	# directory supplied in destination
	def File.download(destination, *src_files)
		src_files.each { |src|
			dest = destination

			if (::File.basename(destination) != File.basename(src))
				dest += ::File::SEPARATOR + File.basename(src)
			end

			src_fd = client.fs.file.new(src, "rb")
			dst_fd = ::File.new(dest, "wb")

			# Keep transferring until EOF is reached...
			begin
				while ((data = src_fd.read) != nil)
					dst_fd.write(data)
				end
			rescue EOFError
			end

			src_fd.close
			dst_fd.close
		}
	end


	##
	#
	# Constructor
	#
	##

	# Initializes and opens the specified file with the specified permissions
	def initialize(name, mode = "r", perms = 0)
		self.client = self.class.client
		self.filed  = _open(name, mode, perms)
	end

	##
	#
	# IO implementators
	#
	##

	# Returns whether or not the file has reach EOF
	def eof
		return self.filed.eof
	end
	
	# Returns the current position of the file pointer
	def pos
		return self.filed.tell
	end

	# Synonym for sysseek
	def seek(offset, whence = SEEK_SET)
		return self.sysseek(offset, whence)
	end

	# Seeks to the supplied offset based on the supplied relativity
	def sysseek(offset, whence = SEEK_SET)
		return self.filed.seek(offset, whence)
	end

protected

	##
	#
	# Internal methods
	#
	##

	# Creates a File channel using the supplied information
	def _open(name, mode = "r", perms = 0)
		return Rex::Post::Meterpreter::Channels::Pools::File.open(
				self.client, name, mode, perms)
	end

	attr_accessor :client

end

end; end; end; end; end; end
