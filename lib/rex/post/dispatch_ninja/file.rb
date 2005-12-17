#!/usr/bin/env ruby

require 'rex/post/file'
require 'rex/post/dispatch_ninja/io'

module Rex
module Post
module DispatchNinja

class File < Rex::Post::DispatchNinja::IO

	include Rex::Post::File

	# setup a class variable for our client pointer
	class <<self
		attr_accessor :client
	end

	protected
	attr_accessor :client
	public

	# !!! make mode/perms work!
	def initialize(name, mode="r", perms=0)
		self.client = self.class.client
		self.filed = _open(name, mode, perms)
	end

	def _open(name, mode="r", perms=0)
		
		client.sendmodule('open')
		client.sendfilename(name)

		res = client.sockread(4).unpack('l')[0]

		client.checksig()

		if res < 0
			raise SystemCallError.new(name, -res)
		end

		return res
	end

	def File.stat(name)
		client.filestat.new(name)
	end

	def File.stat_data(file)

		client.sendmodule('stat')
		client.sendfilename(file)

		data = client.sockread(68)
		res = data[0, 4].unpack('l')[0]

		client.checksig()

		if res < 0
			raise SystemCallError.new(file, -res)
		end

		return data[4 .. -1]
	end
end

end; end; end # DispatchNinja/Post/Rex

