=begin

full file_system module
will be available and recommended usage, allowing Ole::Storage, Dir, and Zip::ZipFile to be
used pretty exchangably down the track. should be possible to write a recursive copy using
the plain api, such that you can copy dirs/files agnostically between any of ole docs, dirs,
and zip files.

i think its okay to have an api like this on top, but there are certain things that ole
does that aren't captured.
ole::storage can have multiple files with the same name, for example, or with / in the
name, and other things that are probably invalid anyway.
i think this should remain an addon, built on top of my core api.
but still the ideas can be reflected in the core, ie, changing the read/write semantics.

once the core changes are complete, this will be a pretty straight forward file to complete.

=end

module Ole
	class Storage
		def file
			@file ||= FileParent.new self
		end

		def dir
			@dir ||= DirParent.new self
		end

		def dirent_from_path path_str
			path = path_str.sub(/^\/*/, '').sub(/\/*$/, '')
			dirent = @root
			return dirent if path.empty?
			path = path.split /\/+/
			until path.empty?
				raise "invalid path #{path_str.inspect}" if dirent.file?
				if tmp = dirent[path.shift]
					dirent = tmp
				else
					# allow write etc later.
					raise "invalid path #{path_str.inspect}"
				end
			end
			dirent
		end

		class FileParent
			def initialize ole
				@ole = ole
			end

			def open path_str, mode='r'
				dirent = @ole.dirent_from_path path_str
				# like Errno::EISDIR
				raise "#{path_str.inspect} is a directory" unless dirent.file?
				io = dirent.io
				if block_given?
					yield io
				else
					io
				end
			end

			alias new :open

			def read path
				open(path) { |f| f.read }
			end

			# crappy copy from Dir.
			def unlink path
				dirent = @ole.dirent_from_path path
				# EPERM 
				raise "operation not permitted #{path.inspect}" unless dirent.file?
				# i think we should free all of our blocks. i think the best way to do that would be
				# like:
				# open(path) { |f| f.truncate 0 }. which should free all our blocks from the
				# allocation table. then if we remove ourself from our parent, we won't be part of
				# the bat at save time.
				# i think if you run repack, all free blocks should get zeroed.
				parent = @ole.dirent_from_path(('/' + path).sub(/\/[^\/]+$/, ''))
				parent.children.delete dirent
				1 # hmmm. as per ::File ?
			end
		end

		class DirParent
			def initialize ole
				@ole = ole
			end

			def open path_str
				dirent = @ole.dirent_from_path path_str
				# like Errno::ENOTDIR
				raise "#{path_str.inspect} is not a directory" unless dirent.dir?
				dir = Dir.new dirent, path_str
				if block_given?
					yield dir
				else
					dir
				end
			end

			# certain Dir class methods proxy in this fashion:
			def entries path
				open(path) { |dir| dir.entries }
			end

			# there are some other important ones, like:
			# chroot (!), mkdir, chdir, rmdir, glob etc etc. for now, i think
			# mkdir, and rmdir are the main ones we'd need to support
			def rmdir path
				dirent = @ole.dirent_from_path path

				# repeating myself
				raise "#{path.inspect} is not a directory" unless dirent.dir?
				# ENOTEMPTY:
				raise "directory not empty #{path.inspect}" unless dirent.children.empty?
				# now delete it, how to do that? the canonical representation that is
				# maintained is the root tree, and the children array. we must remove it
				# from the children array.
				# we need the parent then. this sucks but anyway:
				parent = @ole.dirent_from_path path.sub(/\/[^\/]+$/, '') || '/'
				# note that the way this currently works, on save and repack time this will get
				# reflected. to work properly, ie to make a difference now it would have to re-write
				# the dirent. i think that Ole::Storage#close will handle that. and maybe include a
				# #repack.
				parent.children.delete dirent
				0 # hmmm. as per ::Dir ?
			end

			class Dir
				include Enumerable
				attr_reader :dirent, :path, :entries, :pos

				def initialize dirent, path
					@dirent, @path = dirent, path
					@pos = 0
					# FIXME: hack, and probably not really desired
					@entries = %w[. ..] + @dirent.children.map(&:name)
				end

				def each(&block)
					@entries.each(&block)
				end

				def close
				end

				def read
					@entries[@pos]
				ensure
					@pos += 1 if @pos < @entries.length
				end

				def pos= pos
					@pos = [[0, pos].max, @entries.length].min
				end

				def rewind
					@pos = 0
				end

				alias tell :pos
				alias seek :pos=
			end
		end
	end
end