module Msf
module Session

###
#
# Basic
# -----
#
# This class implements an interactive session using raw input/output in
# only the most basic fashion.
#
###
module Basic

	include Session
	include Interactive

	#
	# Initialize's the raw session
	#
	def initialize(rstream)
		self.rstream = rstream
	end

	#
	# Returns that, yes, indeed, this session supports going interactive with
	# the user.
	#
	def interactive?
		true
	end

	#
	# Description of the session
	#
	def desc
		"Basic I/O"
	end

	#
	# Basic session
	#
	def type
		"basic"
	end
	
	#
	# Returns the local information
	#
	def tunnel_local
		rstream.localinfo
	end

	#
	# Returns the remote peer information
	#
	def tunnel_peer
		rstream.peerinfo
	end
	
	#
	# Closes rstream.
	#
	def cleanup
		rstream.close if (rstream)
		rstream = nil
	end

	#
	# Starts interacting with the session at the most raw level, simply 
	# forwarding input from user_input to rstream and forwarding input from
	# rstream to user_output.
	#
	def interact
		# Call the parent in case it has some work to do
		super 

		eof = false

		# Handle suspend notifications
		handle_suspend

		callcc { |ctx|
			# As long as we're interacting...
			while (self.interacting == true)
				begin
					_interact
				# If we get an interrupt exception, ask the user if they want to
				# abort the interaction.  If they do, then we return out of
				# the interact function and call it a day.
				rescue Interrupt
					if (user_want_abort? == true)
						eof = true
						ctx.call
					end
				rescue EOFError
					dlog("Session #{name} got EOF, closing.", 'core', LEV_1)
					eof = true
					ctx.call
				end
			end
		}

		# Restore the suspend handler
		restore_suspend

		# If we hit end-of-file, then that means we should finish off this
		# session and call it a day.
		framework.sessions.deregister(self) if (eof == true)

		# Return whether or not EOF was reached
		return eof
	end

	#
	# The remote stream handle.  Must inherit from Rex::IO::Stream.
	#
	attr_accessor :rstream

protected

	#
	# Performs the actual raw interaction with the remote side.  This can be
	# overriden by derived classes if they wish to do this another way.
	#
	def _interact
		while self.interacting
			# Select input and rstream
			sd = Rex::ThreadSafe.select([ user_input.fd, rstream.fd ])

			# Cycle through the items that have data
			# From the rstream?  Write to user_output.
			sd[0].each { |s|
				if (s == rstream.fd)
					data = rstream.get

					user_output.print(data)
				# From user_input?  Write to rstream.
				elsif (s == user_input.fd)
					data = user_input.gets

					rstream.put(data)
				end
			} if (sd)
		end
	end

end

end
end
