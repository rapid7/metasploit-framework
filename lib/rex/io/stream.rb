# -*- coding: binary -*-
require 'rex/sync/thread_safe'

module Rex
module IO

###
#
# This mixin is an abstract representation of a streaming connection.  Streams
# extend classes that must implement the following methods:
#
#   syswrite(buffer)
#   sysread(length)
#   shutdown(how)
#   close
#   peerinfo
#   localinfo
#
###
module Stream

	##
	#
	# Abstract methods
	#
	##

	#
	# This method writes the supplied buffer to the stream.  This method
	# intelligent reduces the size of supplied buffers so that ruby doesn't get
	# into a potential global thread blocking state when used on blocking
	# sockets.  That is, this method will send the supplied buffer in chunks
	# of, at most, 32768 bytes.
	#
	def write(buf, opts = {})
		total_sent   = 0
		total_length = buf.length
		block_size   = 32768

		begin
			while( total_sent < total_length )
				s = Rex::ThreadSafe.select( nil, [ fd ], nil, 0.2 )
				if( s == nil || s[0] == nil )
					next
				end
				data = buf[total_sent, block_size]
				sent = fd.write_nonblock( data )
				if sent > 0
					total_sent += sent
				end
			end
		rescue ::Errno::EAGAIN, ::Errno::EWOULDBLOCK
			# Sleep for a half a second, or until we can write again
			Rex::ThreadSafe.select( nil, [ fd ], nil, 0.5 )
			# Decrement the block size to handle full sendQs better
			block_size = 1024
			# Try to write the data again
			retry
		rescue ::IOError, ::Errno::EPIPE
			return nil
		end

		total_sent
	end

	#
	# This method reads data of the supplied length from the stream.
	#
	def read(length = nil, opts = {})

		begin
			return fd.read_nonblock( length )
		rescue ::Errno::EAGAIN, ::Errno::EWOULDBLOCK
			# Sleep for a half a second, or until we can read again
			Rex::ThreadSafe.select( [ fd ], nil, nil, 0.5 )
			# Decrement the block size to handle full sendQs better
			retry
		rescue ::IOError, ::Errno::EPIPE
			return nil
		end
	end

	#
	# Polls the stream to see if there is any read data available.  Returns
	# true if data is available for reading, otherwise false is returned.
	#
	def has_read_data?(timeout = nil)

		# Allow a timeout of "0" that waits almost indefinitely for input, this
		# mimics the behavior of Rex::ThreadSafe.select() and fixes some corner
		# cases of unintentional no-wait timeouts.
		timeout = 3600 if (timeout and timeout == 0)

		begin
			if ((rv = ::IO.select([ fd ], nil, nil, timeout)) and
			    (rv[0]) and
			    (rv[0][0] == fd))
				true
			else
				false
			end
		rescue ::Errno::EBADF, ::Errno::ENOTSOCK
			raise ::EOFError
		rescue StreamClosedError, ::IOError, ::EOFError, ::Errno::EPIPE
			#  Return false if the socket is dead
			return false
		end
	end

	#
	# This method returns the selectable file descriptor, or self by default.
	#
	def fd
		self
	end

	##
	#
	# Common methods
	#
	##

	#
	# This method writes the supplied buffer to the stream by calling the write
	# routine.
	#
	def <<(buf)
		return write(buf.to_s)
	end

	#
	# This method calls get_once() to read pending data from the socket
	#
	def >>
		get_once
	end

	#
	# This method writes to the stream, optionally timing out after a period of
	# time.
	#
	def timed_write(buf, wait = def_write_timeout, opts = {})
		if (wait and wait > 0)
			Timeout.timeout(wait) {
				return write(buf, opts)
			}
		else
			return write(buf, opts)
		end
	end

	#
	# This method reads from the stream, optionally timing out after a period
	# of time.
	#
	def timed_read(length = nil, wait = def_read_timeout, opts = {})
		if (wait and wait > 0)
			Timeout.timeout(wait) {
				return read(length, opts)
			}
		else
			return read(length, opts)
		end
	end

	#
	# This method writes the full contents of the supplied buffer, optionally
	# with a timeout.
	#
	def put(buf, opts = {})
		return 0 if (buf == nil or buf.length == 0)

		send_len = buf.length
		send_idx = 0
		wait     = opts['Timeout'] || 0

		# Keep writing until our send length drops to zero
		while (send_idx < send_len)
			curr_len  = timed_write(buf[send_idx, buf.length-send_idx], wait, opts)

			# If the write operation failed due to an IOError, then we fail.
			return buf.length - send_len if (curr_len == nil)

			send_len -= curr_len
			send_idx += curr_len
		end

		return buf.length - send_len
	end


	#
	# This method emulates the behavior of Pex::Socket::Recv in MSF2
	#
	def get_once(length = -1, timeout = def_read_timeout)

		if (has_read_data?(timeout) == false)
			return nil
		end

		bsize = (length == -1) ? def_block_size : length
		data  = read(bsize)
		raise EOFError if data.nil?
		data
	end

	#
	# This method reads as much data as it can from the wire given a maximum
	# timeout.
	#
	def get(timeout = nil, ltimeout = def_read_loop_timeout, opts = {})
		# For those people who are used to being able to use a negative timeout!
		if (timeout and timeout.to_i < 0)
			timeout = nil
		end

		# No data in the first place? bust.
		if (has_read_data?(timeout) == false)
			return nil
		end

		buf = ""
		lps = 0
		eof = false

		# Keep looping until there is no more data to be gotten..
		while (has_read_data?(ltimeout) == true)
			# Catch EOF errors so that we can handle them properly.
			begin
				temp = read(def_block_size)
			rescue EOFError
				eof = true
			end

			# If we read zero bytes and we had data, then we've hit EOF
			if (temp and temp.length == 0)
				eof = true
			end

			# If we reached EOF and there are no bytes in the buffer we've been
			# reading into, then throw an EOF error.
			if (eof)
				# If we've already read at least some data, then it's time to
				# break out and let it be processed before throwing an EOFError.
				if (buf.length > 0)
					break
				else
					raise EOFError
				end
			end

			break if (temp == nil or temp.empty? == true)

			buf += temp
			lps += 1

			break if (lps >= def_max_loops)
		end

		# Return the entire buffer we read in
		return buf
	end

	##
	#
	# Defaults
	#
	##

	#
	# The default number of seconds to wait for a write operation to timeout.
	#
	def def_write_timeout
		10
	end

	#
	# The default number of seconds to wait for a read operation to timeout.
	#
	def def_read_timeout
		10
	end

	#
	# The default number of seconds to wait while in a read loop after read
	# data has been found.
	#
	def def_read_loop_timeout
		0.1
	end

	#
	# The maximum number of read loops to perform before returning to the
	# caller.
	#
	def def_max_loops
		1024
	end

	#
	# The default block size to read in chunks from the wire.
	#
	def def_block_size
		16384
	end

protected

end

end end

