#!/usr/bin/ruby

require 'Rex/Post/IO'

module Rex
module Post
module DispatchNinja

class IO < Rex::Post::IO

	# setup a class variable for our client pointer
	class <<self
		attr_accessor :client
	end

	def close
		_close(filed)
	end

	def _close(fd)
		client.sendmodule('close')
		client.sockwrite([ fd ].pack('l'))

		res = client.sockread(4).unpack('L')[0]

		client.checksig()

		if res < 0
			raise SystemCallError.new("close(#{fd})", -res)
		end
	end
end

end; end; end # DispatchNinja/Post/Rex

