#!/usr/bin/ruby

require 'Rex/Post/DispatchNinja/File'
require 'Rex/Post/DispatchNinja/FileStat'
require 'Rex/Post/DispatchNinja/Process'
require 'Rex/Post/DispatchNinja/Dir'

module Rex
module Post
module DispatchNinja

class Client

	private
	attr_accessor :sock
	public

	def initialize(sock)
		self.sock = sock

		checksig()
	end

	def brand(klass)
		klass = klass.dup
		klass.client = self
		return klass
	end

	def file
		brand(Rex::Post::DispatchNinja::File)
	end
	def filestat
		brand(Rex::Post::DispatchNinja::FileStat)
	end
	def process
		brand(Rex::Post::DispatchNinja::Process)
	end
	def dir
		brand(Rex::Post::DispatchNinja::Dir)
	end

	def sendmodule(name)
		name = 'lib/Rex/Post/DispatchNinja/modules/' + name
		data = IO.readlines(name, '')[0]
		sockwrite([data.length].pack('V'))
		sockwrite(data)
	end

	def checksig
		if !select( [ sock ], nil, nil, 2)
			puts "Possible sync problem?"
		else
			sig = sockread(4)
			if sig != "AAAA"
				puts "Sig #{sig} didn't match"
			end
		end
	end

	def sendfilename(dir)
		dir += "\x00" # null terminate filename for easy syscall
		sockwrite( [ dir.length ].pack('V') )
		sockwrite(dir)
	end

	# do true full read/write, blocking.  So if I say read 4 bytes, I'll
	# block until I get all 4 bytes
	def sockwrite(data)
		sock.write(data)
	end

	def sockread(len)
		return sock.read(len)
	end

end

end; end; end # DispatchNinja/Post/Rex
