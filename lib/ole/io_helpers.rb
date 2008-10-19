
# move to support?
class IO
	def self.copy src, dst
		until src.eof?
			buf = src.read(4096)
			dst.write buf
		end
	end
end

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
	attr_reader :io, :ranges, :size, :pos
	# +io+ is the parent io object that we are wrapping.
	# 
	# +ranges+ are byte offsets, either
	# 1. an array of ranges [1..2, 4..5, 6..8] or
	# 2. an array of arrays, where the second is length [[1, 1], [4, 1], [6, 2]] for the above
	#    (think the way String indexing works)
	# The +ranges+ provide sequential slices of the file that will be read. they can overlap.
	def initialize io, ranges, opts={}
		@opts = {:close_parent => false}.merge opts
		@io = io
		# convert ranges to arrays. check for negative ranges?
		@ranges = ranges.map { |r| Range === r ? [r.begin, r.end - r.begin] : r }
		# calculate size
		@size = @ranges.inject(0) { |total, (pos, len)| total + len }
		# initial position in the file
		@pos = 0
	end

	def pos= pos, whence=IO::SEEK_SET
		# FIXME support other whence values
		raise NotImplementedError, "#{whence.inspect} not supported" unless whence == IO::SEEK_SET
		# just a simple pos calculation. invalidate buffers if we had them
		@pos = pos
	end

	alias seek :pos=
	alias tell :pos

	def close
		@io.close if @opts[:close_parent]
	end

	def range_and_offset pos
		off = nil
		r = ranges.inject(0) do |total, r|
			to = total + r[1]
			if pos <= to
				off = pos - total
				break r
			end
			to
		end
		# should be impossible for any valid pos, (0...size) === pos
		raise "unable to find range for pos #{pos.inspect}" unless off
		[r, off]
	end

	def eof?
		@pos == @size
	end

	# read bytes from file, to a maximum of +limit+, or all available if unspecified.
	def read limit=nil
		data = ''
		limit ||= size
		# special case eof
		return data if eof?
		r, off = range_and_offset @pos
		i = ranges.index r
		# this may be conceptually nice (create sub-range starting where we are), but
		# for a large range array its pretty wasteful. even the previous way was. but
		# i'm not trying to optimize this atm. it may even go to c later if necessary.
		([[r[0] + off, r[1] - off]] + ranges[i+1..-1]).each do |pos, len|
			@io.seek pos
			if limit < len
				# FIXME this += isn't correct if there is a read error
				# or something.
				@pos += limit
				break data << @io.read(limit) 
			end
			# this can also stuff up. if the ranges are beyond the size of the file, we can get
			# nil here.
			data << @io.read(len)
			@pos += len
			limit -= len
		end
		data
	end

	# you may override this call to update @ranges and @size, if applicable. then write
	# support can grow below
	def truncate size
		raise NotImplementedError, 'truncate not supported'
	end
	# why not? :)
	alias size= :truncate

	def write data
		# short cut. needed because truncate 0 may return no ranges, instead of empty range,
		# thus range_and_offset fails.
		return 0 if data.empty?
		data_pos = 0
		# if we don't have room, we can use the truncate hook to make more space.
		if data.length > @size - @pos
			begin
				truncate @pos + data.length
			rescue NotImplementedError
				# FIXME maybe warn instead, then just truncate the data?
				raise "unable to satisfy write of #{data.length} bytes" 
			end
		end
		r, off = range_and_offset @pos
		i = ranges.index r
		([[r[0] + off, r[1] - off]] + ranges[i+1..-1]).each do |pos, len|
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

	# this will be generalised to a module later
	def each_read blocksize=4096
		yield read(blocksize) until eof?
	end

	# write should look fairly similar to the above.
	
	def inspect
		# the rescue is for empty files
		pos, len = *(range_and_offset(@pos)[0] rescue [nil, nil])
		range_str = pos ? "#{pos}..#{pos+len}" : 'nil'
		"#<#{self.class} io=#{io.inspect} size=#@size pos=#@pos "\
			"current_range=#{range_str}>"
	end
end