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

			while (!src_fd.eof?)
				data = src_fd.read

				if (data == nil)
					next
				end

				dst_fd.write(data)
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
