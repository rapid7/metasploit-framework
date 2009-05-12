# need IO::Mode
require 'ole/support'

#
# = Introduction
#
# +RangesIO+ is a basic class for wrapping another IO object allowing you to arbitrarily reorder
# slices of the input file by providing a list of ranges. Intended as an initial measure to curb
# inefficiencies in the Dirent#data method just reading all of a file's data in one hit, with
# no method to stream it.
# 
# This class will encapuslate the ranges (corresponding to big or small blocks) of any ole file
# and thus allow reading/writing directly to the source bytes, in a streamed fashion (so just
# getting 16 bytes doesn't read the whole thing).
#
# In the simplest case it can be used with a single range to provide a limited io to a section of
# a file.
#
# = Limitations
#
# * No buffering. by design at the moment. Intended for large reads
# 
# = TODO
# 
# On further reflection, this class is something of a joining/optimization of
# two separate IO classes. a SubfileIO, for providing access to a range within
# a File as a separate IO object, and a ConcatIO, allowing the presentation of
# a bunch of io objects as a single unified whole.
# 
# I will need such a ConcatIO if I'm to provide Mime#to_io, a method that will
# convert a whole mime message into an IO stream, that can be read from.
# It will just be the concatenation of a series of IO objects, corresponding to
# headers and boundaries, as StringIO's, and SubfileIO objects, coming from the
# original message proper, or RangesIO as provided by the Attachment#data, that
# will then get wrapped by Mime in a Base64IO or similar, to get encoded on-the-
# fly. Thus the attachment, in its plain or encoded form, and the message as a
# whole never exists as a single string in memory, as it does now. This is a
# fair bit of work to achieve, but generally useful I believe.
# 
# This class isn't ole specific, maybe move it to my general ruby stream project.
# 
class RangesIO
	attr_reader :io, :mode, :ranges, :size, :pos
	# +io+:: the parent io object that we are wrapping.
	# +mode+:: the mode to use
	# +params+:: hash of params.
	# * :ranges - byte offsets, either:
	#   1. an array of ranges [1..2, 4..5, 6..8] or
	#   2. an array of arrays, where the second is length [[1, 1], [4, 1], [6, 2]] for the above
	#      (think the way String indexing works)
	# * :close_parent - boolean to close parent when this object is closed
	#
	# NOTE: the +ranges+ can overlap.
	def initialize io, mode='r', params={}
		mode, params = 'r', mode if Hash === mode
		ranges = params[:ranges]
		@params = {:close_parent => false}.merge params
		@mode = IO::Mode.new mode
		@io = io
		# convert ranges to arrays. check for negative ranges?
		ranges ||= [0, io.size]
		@ranges = ranges.map { |r| Range === r ? [r.begin, r.end - r.begin] : r }
		# calculate size
		@size = @ranges.inject(0) { |total, (pos, len)| total + len }
		# initial position in the file
		@pos = 0

		# handle some mode flags
		truncate 0 if @mode.truncate?
		seek size if @mode.append?
	end

#IOError: closed stream
# get this for reading, writing, everything...
#IOError: not opened for writing

	# add block form. TODO add test for this
	def self.open(*args, &block)
		ranges_io = new(*args)
		if block_given?
			begin;  yield ranges_io
			ensure; ranges_io.close
			end
		else
			ranges_io
		end
	end

	def pos= pos, whence=IO::SEEK_SET
		case whence
		when IO::SEEK_SET
		when IO::SEEK_CUR
			pos += @pos
		when IO::SEEK_END
			pos = @size + pos
		else raise Errno::EINVAL
		end
		raise Errno::EINVAL unless (0..@size) === pos
		@pos = pos
	end

	alias seek :pos=
	alias tell :pos

	def close
		@io.close if @params[:close_parent]
	end

	# returns the [+offset+, +size+], pair inorder to read/write at +pos+
	# (like a partial range), and its index.
	def offset_and_size pos
		total = 0
		ranges.each_with_index do |(offset, size), i|
			if pos <= total + size
				diff = pos - total
				return [offset + diff, size - diff], i
			end
			total += size
		end
		# should be impossible for any valid pos, (0...size) === pos
		raise ArgumentError, "no range for pos #{pos.inspect}"
	end

	def eof?
		@pos == @size
	end

	# read bytes from file, to a maximum of +limit+, or all available if unspecified.
	def read limit=nil
		data = ''
		return data if eof?
		limit ||= size
		partial_range, i = offset_and_size @pos
		# this may be conceptually nice (create sub-range starting where we are), but
		# for a large range array its pretty wasteful. even the previous way was. but
		# i'm not trying to optimize this atm. it may even go to c later if necessary.
		([partial_range] + ranges[i+1..-1]).each do |pos, len|
			@io.seek pos
			if limit < len
				# convoluted, to handle read errors. s may be nil
				s = @io.read limit
				@pos += s.length if s
				break data << s
			end
			# convoluted, to handle ranges beyond the size of the file
			s = @io.read len
			@pos += s.length if s
			data << s
			break if s.length != len
			limit -= len
		end
		data
	end

	# you may override this call to update @ranges and @size, if applicable.
	def truncate size
		raise NotImplementedError, 'truncate not supported'
	end

	# using explicit forward instead of an alias now for overriding.
	# should override truncate.
	def size=	size
		truncate size
	end

	def write data
		# short cut. needed because truncate 0 may return no ranges, instead of empty range,
		# thus offset_and_size fails.
		return 0 if data.empty?
		data_pos = 0
		# if we don't have room, we can use the truncate hook to make more space.
		if data.length > @size - @pos
			begin
				truncate @pos + data.length
			rescue NotImplementedError
				raise IOError, "unable to grow #{inspect} to write #{data.length} bytes" 
			end
		end
		partial_range, i = offset_and_size @pos
		([partial_range] + ranges[i+1..-1]).each do |pos, len|
			@io.seek pos
			if data_pos + len > data.length
				chunk = data[data_pos..-1]
				@io.write chunk
				@pos += chunk.length
				data_pos = data.length
				break
			end
			@io.write data[data_pos, len]
			@pos += len
			data_pos += len
		end
		data_pos
	end
	
	alias << write

	# i can wrap it in a buffered io stream that
	# provides gets, and appropriately handle pos,
	# truncate. mostly added just to past the tests.
	# FIXME
	def gets
		s = read 1024
		i = s.index "\n"
		@pos -= s.length - (i+1)
		s[0..i]
	end
	alias readline :gets

	def inspect
		# the rescue is for empty files
		pos, len = (@ranges[offset_and_size(@pos).last] rescue [nil, nil])
		range_str = pos ? "#{pos}..#{pos+len}" : 'nil'
		"#<#{self.class} io=#{io.inspect}, size=#@size, pos=#@pos, "\
			"range=#{range_str}>"
	end
end

# this subclass of ranges io explicitly ignores the truncate part of 'w' modes.
# only really needed for the allocation table writes etc. maybe just use explicit modes
# for those
# better yet write a test that breaks before I fix it. added nodoc for the 
# time being.
class RangesIONonResizeable < RangesIO # :nodoc:
	def initialize io, mode='r', params={}
		mode, params = 'r', mode if Hash === mode
		flags = IO::Mode.new(mode).flags & ~IO::TRUNC
		super io, flags, params
	end
end

