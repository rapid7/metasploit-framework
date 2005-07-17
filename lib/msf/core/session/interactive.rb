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
	# The local input handle.  Must inherit from Rex::Ui::Text::Input.
	#
	attr_accessor :linput
	#
	# The local output handle.  Must inherit from Rex::Ui::Output.
	#
	attr_accessor :loutput
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
		loutput.print("\n" + query)
		linput.gets
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
