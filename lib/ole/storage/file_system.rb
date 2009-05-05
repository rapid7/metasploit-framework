#
# = Introduction
#
# This file intends to provide file system-like api support, a la <tt>zip/zipfilesystem</tt>.
#
# = TODO
# 
# - need to implement some more IO functions on RangesIO, like #puts, #print
#   etc, like AbstractOutputStream from zipfile.
#
# - check Dir.mkdir, and File.open, and File.rename, to add in filename 
#   length checks (max 32 / 31 or something).
#   do the automatic truncation, and add in any necessary warnings.
#
# - File.split('a/') == File.split('a') == ['.', 'a']
#   the implication of this, is that things that try to force directory
#   don't work. like, File.rename('a', 'b'), should work if a is a file
#   or directory, but File.rename('a/', 'b') should only work if a is
#   a directory. tricky, need to clean things up a bit more.
#   i think a general path name => dirent method would work, with flags
#   about what should raise an error. 
#
# - Need to look at streamlining things after getting all the tests passing,
#   as this file's getting pretty long - almost half the real implementation.
#   and is probably more inefficient than necessary.
#   too many exceptions in the expected path of certain functions.
#
# - should look at profiles before and after switching ruby-msg to use
#   the filesystem api.
#

require 'ole/storage'

module Ole # :nodoc:
	class Storage
		def file
			@file ||= FileClass.new self
		end

		def dir
			@dir ||= DirClass.new self
		end

		# tries to get a dirent for path. return nil if it doesn't exist
		# (change it)
		def dirent_from_path path
			dirent = @root
			path = file.expand_path path
			path = path.sub(/^\/*/, '').sub(/\/*$/, '').split(/\/+/)
			until path.empty?
				return nil if dirent.file?
				return nil unless dirent = dirent/path.shift
			end
			dirent
		end

		class FileClass
			class Stat
				attr_reader :ftype, :size, :blocks, :blksize
				attr_reader :nlink, :uid, :gid, :dev, :rdev, :ino
				def initialize dirent
					@dirent = dirent
					@size = dirent.size
					if file?
						@ftype = 'file'
						bat = dirent.ole.bat_for_size(dirent.size)
						@blocks = bat.chain(dirent.first_block).length
						@blksize = bat.block_size
					else
						@ftype = 'directory'
						@blocks = 0
						@blksize = 0
					end
					# a lot of these are bogus. ole file format has no analogs
					@nlink = 1
					@uid, @gid = 0, 0
					@dev, @rdev = 0, 0
					@ino = 0
					# need to add times - atime, mtime, ctime. 
				end

				alias rdev_major :rdev
				alias rdev_minor :rdev

				def file?
					@dirent.file?
				end

				def directory?
					@dirent.dir?
				end
				
				def size?
					size if file?
				end

				def inspect
					pairs = (instance_variables - ['@dirent']).map do |n|
						"#{n[1..-1]}=#{instance_variable_get n}"
					end
					"#<#{self.class} #{pairs * ', '}>"
				end
			end

			def initialize ole
				@ole = ole
			end

			def expand_path path
				# get the raw stored pwd value (its blank for root)
				pwd = @ole.dir.instance_variable_get :@pwd
				# its only absolute if it starts with a '/'
				path = "#{pwd}/#{path}" unless path =~ /^\//
				# at this point its already absolute. we use File.expand_path
				# just for the .. and . handling
				# No longer use RUBY_PLATFORM =~ /win/ as it matches darwin. better way?
				File.expand_path(path)[File::ALT_SEPARATOR == "\\" ? (2..-1) : (0..-1)]
			end

			# +orig_path+ is just so that we can use the requested path
			# in the error messages even if it has been already modified
			def dirent_from_path path, orig_path=nil
				orig_path ||= path
				dirent = @ole.dirent_from_path path
				raise Errno::ENOENT,  orig_path unless dirent
				raise Errno::EISDIR, orig_path if dirent.dir?
				dirent
			end
			private :dirent_from_path

			def exists? path
				!!@ole.dirent_from_path(path)
			end
			alias exist? :exists?

			def file? path
				dirent = @ole.dirent_from_path path
				dirent and dirent.file?
			end

			def directory? path
				dirent = @ole.dirent_from_path path
				dirent and dirent.dir?
			end

			def open path, mode='r', &block
				if IO::Mode.new(mode).create?
					begin
						dirent = dirent_from_path path
					rescue Errno::ENOENT
						# maybe instead of repeating this everywhere, i should have
						# a get_parent_dirent function.
						parent_path, basename = File.split expand_path(path)
						parent = @ole.dir.send :dirent_from_path, parent_path, path
						parent.children << dirent = Dirent.new(@ole, :type => :file, :name => basename)
					end
				else
					dirent = dirent_from_path path
				end
				dirent.open mode, &block
			end

			# explicit wrapper instead of alias to inhibit block
			def new path, mode='r'
				open path, mode
			end

			def size path
				dirent_from_path(path).size
			rescue Errno::EISDIR
				# kind of arbitrary. I'm getting 4096 from ::File, but
				# the zip tests want 0.
				0
			end
			
			def size? path
				dirent_from_path(path).size
				# any other exceptions i need to rescue?
			rescue Errno::ENOENT, Errno::EISDIR
				nil
			end

			def stat path
				# we do this to allow dirs.
				dirent = @ole.dirent_from_path path
				raise Errno::ENOENT, path unless dirent
				Stat.new dirent
			end

			def read path
				open path, &:read
			end

			# most of the work this function does is moving the dirent between
			# 2 parents. the actual name changing is quite simple.
			# File.rename can move a file into another folder, which is why i've
			# done it too, though i think its not always possible...
			#
			# FIXME File.rename can be used for directories too....
			def rename from_path, to_path
				# check what we want to rename from exists. do it this
				# way to allow directories.
				dirent = @ole.dirent_from_path from_path
				raise Errno::ENOENT, from_path unless dirent
				# delete what we want to rename to if necessary
				begin
					unlink to_path
				rescue Errno::ENOENT
					# we actually get here, but rcov doesn't think so. add 1 + 1 to
					# keep rcov happy for now... :)
					1 + 1
				end
				# reparent the dirent
				from_parent_path, from_basename = File.split expand_path(from_path)
				to_parent_path, to_basename = File.split expand_path(to_path)
				from_parent = @ole.dir.send :dirent_from_path, from_parent_path, from_path
				to_parent = @ole.dir.send :dirent_from_path, to_parent_path, to_path
				from_parent.children.delete dirent
				# and also change its name
				dirent.name = to_basename
				to_parent.children << dirent
				0
			end

			# crappy copy from Dir.
			def unlink(*paths)
				paths.each do |path|
					dirent = @ole.dirent_from_path path
					# i think we should free all of our blocks from the
					# allocation table.
					# i think if you run repack, all free blocks should get zeroed,
					# but currently the original data is there unmodified.
					open(path) { |f| f.truncate 0 }
					# remove ourself from our parent, so we won't be part of the dir
					# tree at save time.
					parent_path, basename = File.split expand_path(path)
					parent = @ole.dir.send :dirent_from_path, parent_path, path
					parent.children.delete dirent
				end
				paths.length # hmmm. as per ::File ?
			end
			alias delete :unlink
		end

		#
		# an *instance* of this class is supposed to provide similar methods
		# to the class methods of Dir itself.
		#
		# pretty complete. like zip/zipfilesystem's implementation, i provide
		# everything except chroot and glob. glob could be done with a glob
		# to regex regex, and then simply match in the entries array... although
		# recursive glob complicates that somewhat.
		#
		# Dir.chroot, Dir.glob, Dir.[], and Dir.tmpdir is the complete list.
		class DirClass
			def initialize ole
				@ole = ole
				@pwd = ''
			end

			# +orig_path+ is just so that we can use the requested path
			# in the error messages even if it has been already modified
			def dirent_from_path path, orig_path=nil
				orig_path ||= path
				dirent = @ole.dirent_from_path path
				raise Errno::ENOENT,  orig_path unless dirent
				raise Errno::ENOTDIR, orig_path unless dirent.dir?
				dirent
			end
			private :dirent_from_path

			def open path
				dir = Dir.new path, entries(path)
				if block_given?
					yield dir
				else
					dir
				end
			end

			# as for file, explicit alias to inhibit block
			def new path
				open path
			end

			# pwd is always stored without the trailing slash. we handle
			# the root case here
			def pwd
				if @pwd.empty?
					'/'
				else
					@pwd
				end
			end
			alias getwd :pwd

			def chdir orig_path
				# make path absolute, squeeze slashes, and remove trailing slash
				path = @ole.file.expand_path(orig_path).gsub(/\/+/, '/').sub(/\/$/, '')
				# this is just for the side effects of the exceptions if invalid
				dirent_from_path path, orig_path
				if block_given?
					old_pwd = @pwd
					begin
						@pwd = path
						yield
					ensure
						@pwd = old_pwd
					end
				else
					@pwd = path
					0
				end
			end	

			def entries path
				dirent = dirent_from_path path
				# Not sure about adding on the dots...
				entries = %w[. ..] + dirent.children.map(&:name)
				# do some checks about un-reachable files
				seen = {}
				entries.each do |n|
					Log.warn "inaccessible file (filename contains slash) - #{n.inspect}" if n['/']
					Log.warn "inaccessible file (duplicate filename) - #{n.inspect}" if seen[n]
					seen[n] = true
				end
				entries
			end

			def foreach path, &block
				entries(path).each(&block)
			end

			# there are some other important ones, like:
			# chroot (!), glob etc etc. for now, i think
			def mkdir path
				# as for rmdir below:
				parent_path, basename = File.split @ole.file.expand_path(path)
				# note that we will complain about the full path despite accessing
				# the parent path. this is consistent with ::Dir
				parent = dirent_from_path parent_path, path
				# now, we first should ensure that it doesn't already exist
				# either as a file or a directory.
				raise Errno::EEXIST, path if parent/basename
				parent.children << Dirent.new(@ole, :type => :dir, :name => basename)
				0
			end

			def rmdir path
				dirent = dirent_from_path path
				raise Errno::ENOTEMPTY, path unless dirent.children.empty?

				# now delete it, how to do that? the canonical representation that is
				# maintained is the root tree, and the children array. we must remove it
				# from the children array.
				# we need the parent then. this sucks but anyway:
				# we need to split the path. but before we can do that, we need
				# to expand it first. eg. say we need the parent to unlink
				# a/b/../c. the parent should be a, not a/b/.., or a/b.
				parent_path, basename = File.split @ole.file.expand_path(path)
				# this shouldn't be able to fail if the above didn't
				parent = dirent_from_path parent_path
				# note that the way this currently works, on save and repack time this will get
				# reflected. to work properly, ie to make a difference now it would have to re-write
				# the dirent. i think that Ole::Storage#close will handle that. and maybe include a
				# #repack.
				parent.children.delete dirent
				0 # hmmm. as per ::Dir ?
			end
			alias delete :rmdir
			alias unlink :rmdir

			# note that there is nothing remotely ole specific about
			# this class. it simply provides the dir like sequential access
			# methods on top of an array.
			# hmm, doesn't throw the IOError's on use of a closed directory...
			class Dir
				include Enumerable

				attr_reader :path
				def initialize path, entries
					@path, @entries, @pos = path, entries, 0
					@closed = false
				end
				
				def pos
					raise IOError if @closed
					@pos
				end

				def each(&block)
					raise IOError if @closed
					@entries.each(&block)
				end

				def close
					@closed = true
				end

				def read
					raise IOError if @closed
					@entries[pos]
				ensure
					@pos += 1 if pos < @entries.length
				end

				def pos= pos
					raise IOError if @closed
					@pos = [[0, pos].max, @entries.length].min
				end

				def rewind
					raise IOError if @closed
					@pos = 0
				end

				alias tell :pos
				alias seek :pos=
			end
		end
	end
end

