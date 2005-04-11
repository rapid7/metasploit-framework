#!/usr/bin/ruby

require 'Rex/Post/IO'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi

class IO < Rex::Post::IO

	def read(length = nil, flags = nil)
		recv(length, flags)
	end

	def recv(length = nil, flags = nil)
		filed.recv(length)
	end

	def write(buf, length = nil, flags = nil)
		send(buf, length, flags)
	end

	def send(buf, length = nil, flags = nil)
		filed.send(buf, length)
	end

	def close
		filed.close
	end

end

end; end; end; end; end
