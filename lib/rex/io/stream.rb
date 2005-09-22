require 'rex/sync/thread_safe'

module Rex
module IO

###
#
# Stream
# ------
# 
# This mixin is an abstract representation of a streaming connection.
#
###
module Stream

	##
	#
	# Abstract methods
	#
	##

	#
	# Set the stream to blocking or non-blocking
	#
	def blocking=(tf)
	end

	#
	# Check to see if the stream is blocking or non-blocking
	#
	def blocking
	end

	#
	# Writes data to the stream.
	#
	def write(buf, opts = {})
		fd.syswrite(buf)
	end

	#
	# Reads data from the stream.
	#
	def read(length = nil, opts = {})
		length = 16384 unless length

		fd.sysread(length)
	end

	#
	# Shuts down the stream for reading, writing, or both.
	#
	def shutdown(how = SW_BOTH)
		fd.shutdown(how)
	end

	#
	# Closes the stream and allows for resource cleanup
	#
	def close
		fd.close
	end

	#
	# Polls the stream to see if there is any read data available.  Returns
	# true if data is available for reading, otherwise false is returned.
	#
	def has_read_data?(timeout = nil)
		Rex::ThreadSafe.select([ fd ], nil, nil, timeout)
	end

	#
	# Returns the file descriptor that can be polled via select, if any.
	#
	def poll_fd
	end

	#
	# Wrapper for poll_fd
	#
	def fd
		poll_fd
	end

	#
	# Returns peer information, such as host and port.
	#
	def peerinfo
	end

	#
	# Returns local information, such as host and port.
	#
	def localinfo
	end

	##
	#
	# Common methods
	#
	##

	#
	# Writes data to the stream
	#
	def <<(buf)
		return write(buf.to_s)
	end

	#
	# Writes to the stream, optionally timing out after a period of time
	#
	def timed_write(buf, wait = def_write_timeout, opts = {})
		if (wait and wait > 0)
			timeout(wait) {
				return write(buf, opts)
			}
		else
			return write(buf, opts)
		end
	end

	#
	# Reads from the stream, optionally timing out after a period of time
	#
	def timed_read(length = nil, wait = def_read_timeout, opts = {})
		if (wait and wait > 0)
			timeout(wait) {
				return read(length, opts)
			}
		else
			return read(length, opts)
		end
	end

	#
	# Write the full contents of the supplied buffer
	#
	def put(buf, opts = {})
		send_buf = buf.dup()
		send_len = send_buf.length
		wait     = opts['Timeout'] || 0

		# Keep writing until our send length drops to zero
		while (send_len > 0)
			curr_len  = timed_write(send_buf, wait, opts)
			send_len -= curr_len
			send_buf.slice!(0, curr_len)
		end

		return true
	end

	#
	# Read as much data as possible from the pipe
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

	def def_write_timeout
		return 10
	end

	def def_read_timeout
		return 10
	end
	
	def def_read_loop_timeout
		return 0.5
	end

	def def_max_loops
		return 1024
	end

	def def_block_size
		return 16384
	end

protected

end

end end
