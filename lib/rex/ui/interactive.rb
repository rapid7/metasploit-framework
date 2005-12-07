module Rex
module Ui

###
#
# This class implements the stubs that are needed to provide an interactive
# user interface that is backed against something arbitrary.
#
###
module Interactive

	#
	# Interactive sessions by default may interact with the local user input
	# and output.
	#
	include Rex::Ui::Subscriber

	#
	# Starts interacting with the session at the most raw level, simply 
	# forwarding input from user_input to rstream and forwarding input from
	# rstream to user_output.
	#
	def interact
		self.interacting = true

		eof = false

		# Handle suspend notifications
		handle_suspend

		begin
			callcc { |ctx|
				# As long as we're interacting...
				while (self.interacting == true)
					begin
						_interact
					# If we get an interrupt exception, ask the user if they want to
					# abort the interaction.  If they do, then we return out of
					# the interact function and call it a day.
					rescue Interrupt
						if (_interrupt)
							eof = true
							ctx.call
						end
					# If we reach EOF or the connection is reset...
					rescue EOFError, Errno::ECONNRESET, IOError
						eof = true
						ctx.call
					end
				end
			}
		ensure
			# Restore the suspend handler
			restore_suspend
		end

		# If we've hit eof, call the interact complete handler
		_interact_complete if (eof == true)
		
		# Return whether or not EOF was reached
		return eof
	end

	#
	# Whether or not the session is currently being interacted with
	#
	attr_reader   :interacting

protected

	attr_writer   :interacting # :nodoc:
	#
	# The original suspend proc.
	#
	attr_accessor :orig_suspend

	#
	# Stub method that is meant to handler interaction
	#
	def _interact
	end

	#
	# Called when an interrupt is sent.
	#
	def _interrupt
		true
	end

	#
	# Called when a suspend is sent.
	#
	def _suspend
		false
	end

	#
	# Called when interaction has completed and one of the sides has closed.
	#
	def _interact_complete
		true
	end

	#
	# Read from remote and write to local.
	#
	def _stream_read_remote_write_local(stream)
		data = stream.get

		user_output.print(data)
	end

	#
	# Read from local and write to remote.
	#
	def _stream_read_local_write_remote(stream)
		data = user_input.gets

		stream.put(data)
	end

	#
	# The local file descriptor handle.
	#
	def _local_fd
		user_input.fd
	end

	#
	# The remote file descriptor handle.
	#
	def _remote_fd(stream)
		stream.fd
	end

	#
	# Interacts with two streaming connections, reading data from one and
	# writing it to the other.  Both are expected to implement Rex::IO::Stream.
	#
	def interact_stream(stream)
		while self.interacting
			# Select input and rstream
			sd = Rex::ThreadSafe.select([ _local_fd, _remote_fd(stream) ])

			# Cycle through the items that have data
			# From the stream?  Write to user_output.
			sd[0].each { |s|
				if (s == _remote_fd(stream))
					_stream_read_remote_write_local(stream)
				# From user_input?  Write to stream.
				elsif (s == _local_fd)
					_stream_read_local_write_remote(stream)
				end
			} if (sd)
		end
	
	end

	#
	# Installs a signal handler to monitor suspend signal notifications.
	#
	def handle_suspend
		if (orig_suspend == nil)
			begin
				self.orig_suspend = Signal.trap("TSTP") {
					_suspend
				}
			rescue
			end
		end
	end

	#
	# Restores the previously installed signal handler for suspend
	# notifications.
	#
	def restore_suspend
		if (orig_suspend)
			begin
				Signal.trap("TSTP", orig_suspend)
			rescue
			end

			self.orig_suspend = nil
		end
	end

	#
	# Prompt the user for input if possible.
	#
	def prompt(query)
		if (user_output and user_input)
			user_output.print("\n" + query)
			user_input.sysread(2)
		end
	end
	
	#
	# Check the return value of a yes/no prompt
	#
	def prompt_yesno(query)
		(prompt(query + " [y/N]  ") =~ /^y/i) ? true : false
	end

end

end
end
