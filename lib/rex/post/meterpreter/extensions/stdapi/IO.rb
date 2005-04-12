#!/usr/bin/ruby

require 'Rex/Post/IO'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi

class IO < Rex::Post::IO

	def read(length = nil, flags = nil)
		filed.read(length)
	end

	# Synonym for read
	def recv(length = nil, flags = nil)
		read(length, flags)
	end

	def write(buf, length = nil, flags = nil)
		filed.write(buf, length)
	end

	# Synonym for write
	def send(buf, length = nil, flags = nil)
		write(buf, length, flags)
	end

	def close
		filed.close
	end

end

end; end; end; end; end
