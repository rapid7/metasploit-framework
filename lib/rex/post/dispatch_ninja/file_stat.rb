#!/usr/bin/env ruby

require 'rex/post/file_stat'

module Rex
module Post
module DispatchNinja

class FileStat < Rex::Post::FileStat

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
	class <<self
		attr_accessor :client
	end

	def initialize(file)
		self.stathash = parse_struct_stat(self.class.client.file.stat_data(file))
	end
	def parse_struct_stat(data)
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
end
end; end; end # DispatchNinja/Post/Rex
