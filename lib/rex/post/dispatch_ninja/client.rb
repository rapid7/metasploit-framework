#!/usr/bin/env ruby

require 'rex/post/dispatch_ninja/file'
require 'rex/post/dispatch_ninja/file_stat'
require 'rex/post/dispatch_ninja/process'
require 'rex/post/dispatch_ninja/dir'

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

	# Get a File-like class
	def file
		brand(Rex::Post::DispatchNinja::File)
	end
	# Get a File::Stat-like class
	def filestat
		brand(Rex::Post::DispatchNinja::FileStat)
	end
	# Get a Process-like class
	def process
		brand(Rex::Post::DispatchNinja::Process)
	end
	# Get a Dir-like class
	def dir
		brand(Rex::Post::DispatchNinja::Dir)
	end

	def sendmodule(name)
		name = 'lib/Rex/Post/DispatchNinja/modules/' + name
		data = ::IO.readlines(name, '')[0]
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

	protected

	def brand(klass)
		klass = klass.dup
		klass.client = self
		return klass
	end
end

end; end; end # DispatchNinja/Post/Rex
