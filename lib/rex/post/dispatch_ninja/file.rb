#!/usr/bin/ruby

require 'Rex/Post/File'

module Rex
module Post
module DispatchNinja

class File < Rex::Post::File

	# setup a class variable for our client pointer
	class <<self
		attr_accessor :client
	end

	def File.stat(name)
		client.filestat.new(name)
	end

	def File.stat_data(file)

		client.sendmodule('stat')
		client.sendfilename(file)

		data = client.sockread(68)
		res = data[0, 4].unpack('l')[0]

		# throw exception! blah!

		client.checksig()

		return data[4 .. -1]
	end
end

end; end; end # DispatchNinja/Post/Rex

