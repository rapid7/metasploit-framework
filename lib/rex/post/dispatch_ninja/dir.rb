#!/usr/bin/ruby

require 'Rex/DispatchNinja/Stat'

module Rex
module Post
module DispatchNinja

class File < Rex::Post::File

	#
	# Class Methods
	#

	@@structstat = [
	  'st_dev',     2,
	  'pad1',       2,
	  'st_ino',     4,
	  'st_mode',    2,
	  'st_nlink',   2,
	  'st_uid',     2,
	  'st_gid',     2,
	  'st_rdev',    2,
	  'pad2',       2,
	  'st_size',    4,
	  'st_blksize', 4,
	  'st_blocks',  4,
	  'st_atime',   4,
	  'unused1',    4,
	  'st_mtime',   4,
	  'unused2',    4,
	  'st_ctime',   4,
	  'unused3',    4,
	  'unused4',    4,
	  'unused5',    4
	]

	# setup a class variable for our client pointer
	class <<self
		attr_accessor :client
	end

	def File.stat(file)
		return client.filestat.new(file)
	end
	def ls(dir)

		sendmodule('ls')

		sendfilename(dir)
		
		res = sockread(4).unpack('l')[0] # ug, not portable, later...

		files = [ ]

		while true
			len = sockread(2).unpack('S')[0]
			break if len == 0
			files << sockread(len)
		end

		checksig()

		return [ res, files ]
	end

	def File.stat_hash(file)

		client.sendmodule('stat')
		client.sendfilename(file)

		data = client.sockread(68)
		res = data[0, 4].unpack('l')[0]

		# throw exception! blah!

		client.checksig()

		data = data[4 .. -1]

		elements = @@structstat
		hash = { }
		i = 0
		o = 0
		while i < elements.length
			name = elements[i]
			size = elements[i + 1]
			i += 2

			e = data[o, size].unpack(size == 2 ? 'S' : 'L')[0]
			o += size

			hash[name] = e
		end

		return(hash)
	end

	#
	# Instance Methods
	#
	
	# setup an instance variable, just for ease and copy it over..
	# and so you can change it instance wise
	private
	attr_accessor :client
	public

	def initialize()
		self.client = self.class.client
	end


end

end; end; end # DispatchNinja/Post/Rex

