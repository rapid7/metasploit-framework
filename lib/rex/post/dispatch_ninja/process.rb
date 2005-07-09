#!/usr/bin/ruby

require 'rex/post/process'

module Rex
module Post
module DispatchNinja

class Process < Rex::Post::Process
	class <<self
		attr_accessor :client
	end

	def Process.getresuid()

		# gotta fix this, getresuid could fail
		# I don't transfer the return value on the wire...

		client.sendmodule('getresuid')
		data = client.sockread(16)
		# fsking getresuid/getresuid32
		data[6, 2] = data[10, 2] = data[14, 2] = "\x00\x00"
		data = data.unpack('lL3')
		res = data[0]

		client.checksig()

		if res < 0
			raise SystemCallError.new("getresuid()", -res)
		end

		return data[1, 3] # return the 3 uids
	end

	def Process.pid()
		client.sendmodule('getpid')
		data = client.sockread(4)
		client.checksig
		return data.unpack('V')[0]
	end

	def Process.ppid()
		client.sendmodule('getppid')
		data = client.sockread(4)
		client.checksig
		return data.unpack('V')[0]
	end
end

end; end; end # DispatchNinja/Post/Rex

