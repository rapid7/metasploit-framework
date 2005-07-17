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
	# forwarding input from linput to rstream and forwarding input from
	# rstream to loutput.
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
	# The local input handle.  Must inherit from Rex::Ui::Text::Input.
	#
	attr_accessor :linput
	#
	# The local output handle.  Must inherit from Rex::Ui::Output.
	#
	attr_accessor :loutput
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
			sd = Rex::ThreadSafe.select([ linput.fd, rstream.fd ])

			# Cycle through the items that have data
			# From the rstream?  Write to linput.
			sd[0].each { |s|
				if (s == rstream.fd)
					data = rstream.get

					loutput.print(data)
				# From linput?  Write to rstream.
				elsif (s == linput.fd)
					data = linput.gets

					rstream.put(data)
				end
			} if (sd)
		end
	end

end

end
end
