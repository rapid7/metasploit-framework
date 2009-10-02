#!/usr/bin/env ruby

require 'rex/post/file'
require 'rex/post/meterpreter/channel'
require 'rex/post/meterpreter/channels/pools/file'
require 'rex/post/meterpreter/extensions/stdapi/stdapi'
require 'rex/post/meterpreter/extensions/stdapi/fs/io'
require 'rex/post/meterpreter/extensions/stdapi/fs/file_stat'
require 'fileutils'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Fs

###
#
# This class implements the Rex::Post::File interface and wraps interaction
# with files on the remote machine.
#
###
class File < Rex::Post::Meterpreter::Extensions::Stdapi::Fs::IO

SEPARATOR = "\\"
Separator = "\\"

	include Rex::Post::File
	
	class <<self
		attr_accessor :client
	end

	#
	# Returns the base name of the supplied file path to the caller.
	#
	def File.basename(*a)
		path = a[0]
		sep  = "\\" + File::SEPARATOR

		# I suck at regex.
		path =~ /(.*)#{sep}(.*)$/

		return $2 || path
	end

	#
	# Expands a file path, substituting all environment variables, such as
	# %TEMP%.
	#
	def File.expand_path(path)
		request = Packet.create_request('stdapi_fs_file_expand_path')

		request.add_tlv(TLV_TYPE_FILE_PATH, path)

		response = client.send_request(request)
		
		return response.get_tlv_value(TLV_TYPE_FILE_PATH)
	end

	#
	# Performs a stat on a file and returns a FileStat instance.
	#
	def File.stat(name)
		return client.fs.filestat.new(name)
	end

	#
	# Upload one or more files to the remote computer the remote
	# directory supplied in destination.
	#
	def File.upload(destination, *src_files, &stat)
		src_files.each { |src|
			dest = destination

			stat.call('uploading', src, dest) if (stat)
			if (File.basename(destination) != ::File.basename(src))
				dest += File::SEPARATOR + ::File.basename(src)
			end

			upload_file(dest, src)
			stat.call('uploaded', src, dest) if (stat)
		}
	end

	#
	# Upload a single file.
	#
	def File.upload_file(dest_file, src_file)
		# Open the file on the remote side for writing and read
		# all of the contents of the local file
		dest_fd = client.fs.file.new(dest_file, "wb")
		src_buf = ''
		
		::File.open(src_file, 'rb') { |f|
			src_buf = f.read(f.stat.size)
		}

		begin
			dest_fd.write(src_buf)
		ensure
			dest_fd.close
		end
	end

	#
	# Download one or more files from the remote computer to the local 
	# directory supplied in destination.
	#
	def File.download(destination, *src_files, &stat)
		src_files.each { |src|
			dest = destination

			stat.call('downloading', src, dest) if (stat)

			if (::File.basename(destination) != File.basename(src))
				dest += ::File::SEPARATOR + File.basename(src)
			end

			download_file(dest, src)
			
			stat.call('downloaded', src, dest) if (stat)
		}
	end

	#
	# Download a single file.
	#
	def File.download_file(dest_file, src_file)
		src_fd = client.fs.file.new(src_file, "rb")
		::FileUtils.mkdir_p(::File.dirname(dest_file))
		dst_fd = ::File.new(dest_file, "wb")

		# Keep transferring until EOF is reached...
		begin
			while ((data = src_fd.read) != nil)
				dst_fd.write(data)
			end
		rescue EOFError
		ensure
			src_fd.close
			dst_fd.close
		end
	end

	##
	#
	# Constructor
	#
	##

	#
	# Initializes and opens the specified file with the specified permissions.
	#
	def initialize(name, mode = "r", perms = 0)
		self.client = self.class.client
		self.filed  = _open(name, mode, perms)
	end

	##
	#
	# IO implementators
	#
	##

	#
	# Returns whether or not the file has reach EOF.
	#
	def eof
		return self.filed.eof
	end

	#
	# Returns the current position of the file pointer.
	#
	def pos
		return self.filed.tell
	end

	#
	# Synonym for sysseek.
	#
	def seek(offset, whence = SEEK_SET)
		return self.sysseek(offset, whence)
	end

	#
	# Seeks to the supplied offset based on the supplied relativity.
	#
	def sysseek(offset, whence = SEEK_SET)
		return self.filed.seek(offset, whence)
	end

protected

	##
	#
	# Internal methods
	#
	##

	#
	# Creates a File channel using the supplied information.
	#
	def _open(name, mode = "r", perms = 0)
		return Rex::Post::Meterpreter::Channels::Pools::File.open(
				self.client, name, mode, perms)
	end

	attr_accessor :client # :nodoc:

end

end; end; end; end; end; end
