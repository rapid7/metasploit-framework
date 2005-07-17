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
	# Returns that, yes, indeed, this session supports going interactive with
	# the user.
	#
	def interactive?
		true
	end

	#
	# Starts interacting with the session.
	#
	def interact
		self.interacting = true
	end

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
