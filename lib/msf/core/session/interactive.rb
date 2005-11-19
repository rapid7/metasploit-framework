require 'rex/ui'

module Msf
module Session

###
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
	include Rex::Ui::Interactive

	#
	# Initializes the session.
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
	# Returns the local information.
	#
	def tunnel_local
		rstream.localinfo
	end

	#
	# Returns the remote peer information.
	#
	def tunnel_peer
		begin
			rstream.peerinfo
		rescue
			framework.sessions.deregister(sid)
		end
	end

	#
	# Run an arbitrary command as if it came from user input.
	#
	def run_cmd(cmd)
	end
	
	#
	# Closes rstream.
	#
	def cleanup
		rstream.close if (rstream)
		rstream = nil
	end

	#
	# The remote stream handle.  Must inherit from Rex::IO::Stream.
	#
	attr_accessor :rstream

protected

	#
	# Stub method that is meant to handler interaction.
	#
	def _interact
	end

	#
	# Check to see if the user wants to abort.
	#
	def _interrupt
		user_want_abort?
	end

	#
	# Check to see if we should suspend.
	#
	def _suspend
		# Ask the user if they would like to background the session
		if (prompt_yesno("Background session #{name}?") == true)
			self.interacting = false
		end
	end

	#
	# If the session reaches EOF, deregister it.
	#
	def _interact_complete
		framework.sessions.deregister(self)
	end

	#
	# Checks to see if the user wants to abort.
	#
	def user_want_abort?
		prompt_yesno("Abort session #{name}?")
	end

end

end
end
