#!/usr/bin/ruby

require 'Rex/Post/Dir'

module Rex
module Post
module DispatchNinja

class Dir < Rex::Post::Dir

	class <<self
		attr_accessor :client
	end

	#--

	def Dir.entries(name)

		client.sendmodule('ls')

		client.sendfilename(name)
		
		res = client.sockread(4).unpack('l')[0] # ug, not portable, later...

		files = [ ]

		while true
			len = client.sockread(2).unpack('S')[0]
			break if len == 0
			files << client.sockread(len)
		end

		client.checksig()

		if res < 0 # eek! error!
			raise SystemCallError.new(name, -res)
		end

		return files
	end

	#++
end

end; end; end # DispatchNinja/Post/Rex
