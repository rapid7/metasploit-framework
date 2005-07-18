module Msf
module Session

###
#
# Interactive
# -----------
#
# This class implements the stubs that are needed to provide an interactive
# session.
#
###
module Interactive

	#
	# Interactive sessions by default may interact with the local user input
	# and output.
	#
	include Rex::Ui::Subscriber

	#
	# Initialize's the session
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
		self.interacting = true

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
				# If we reach EOF or the connection is reset...
				rescue EOFError, Errno::ECONNRESET
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
	#
	# Whether or not the session is currently being interacted with
	#
	attr_reader   :interacting

protected

	attr_writer   :interacting
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
	# Checks to see if the user wants to abort
	#
	def user_want_abort?
		prompt_yesno("Abort session #{name}? [y/N]  ")
	end

	#
	# Installs a signal handler to monitor suspend signal notifications.
	#
	def handle_suspend
		if (orig_suspend == nil)
			self.orig_suspend = Signal.trap("TSTP") {
				# Ask the user if they would like to background the session
				if (prompt_yesno("Background session #{name}? [y/N]  ") == true)
					self.interacting = false
				end
			}
		end
	end

	#
	# Restores the previously installed signal handler for suspend
	# notifications.
	#
	def restore_suspend
		if (orig_suspend)
			Signal.trap("TSTP", orig_suspend)

			self.orig_suspend = nil
		end
	end

	def prompt(query)
		if (user_output and user_input)
			user_output.print("\n" + query)
			user_input.gets
		end
	end
	
	#
	# Check the return value of the prompt
	#
	def prompt_yesno(query)
		(prompt(query) =~ /^y/i) ? true : false
	end

end

end
end
