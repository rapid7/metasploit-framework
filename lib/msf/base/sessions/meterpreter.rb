require 'msf/base'
require 'rex/post/meterpreter'

module Msf
module Sessions

###
#
# Meterpreter
# -----------
#
# This class represents a session compatible interface to a meterpreter server
# instance running on a remote machine.  It provides the means of interacting
# with the server instance both at an API level as well as at a console level.
#
###
class Meterpreter < Rex::Post::Meterpreter::Client

	#
	# The meterpreter session is interactive
	#
	include Msf::Session
	include Msf::Session::Interactive

	def initialize(rstream)
		super

		#
		# Initialize the meterpreter client
		#
		self.init_meterpreter(rstream)

		#
		# Create the console instance
		#
		self.console = Rex::Post::Meterpreter::Ui::Console.new(self)
	end

	##
	#
	# Msf::Session overrides
	#
	##
	
	def desc
		"Meterpreter"
	end

	def type
		"meterpreter"
	end

	##
	#
	# Msf::Session::Interactive implementors
	#
	##

	#
	# Initializes the console's I/O handles
	#
	def init_ui(input, output)
		console.init_ui(input, output)
	end

	#
	# Resets the console's I/O handles
	#
	def reset_ui
		console.reset_ui
	end

	#
	# Interacts with the meterpreter client at a user interface level
	#
	def _interact
		# Call the console interaction subsystem of the meterpreter client and
		# pass it a block that returns whether or not we should still be
		# interacting.  This will allow the shell to abort if interaction is
		# canceled.
		console.interact { self.interacting }

		# If the stop flag has been set, then that means the user exited.  Raise
		# the EOFError so we can drop this bitch like a bad habit.
		raise EOFError if (console.stopped? == true)
	end

protected

	attr_accessor :rstream, :console

end

end
end
