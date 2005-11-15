require 'msf/base'
require 'rex/post/meterpreter'

module Msf
module Sessions

###
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
	include Msf::Session::Comm

	#
	# Initializes a meterpreter session instance using the supplied rstream
	# that is to be used as the client's connection to the server.
	#
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

	#
	# Returns the session type as being 'meterpreter'.
	#
	def self.type
		"meterpreter"
	end

	##
	#
	# Msf::Session overrides
	#
	##

	#
	# Returns the session description.
	#
	def desc
		"Meterpreter"
	end

	#
	# Calls the class method.
	#
	def type
		self.class.type
	end

	##
	#
	# Msf::Session::Interactive implementors
	#
	##

	#
	# Initializes the console's I/O handles.
	#
	def init_ui(input, output)
		console.init_ui(input, output)
		console.set_log_source(log_source)
	end

	#
	# Resets the console's I/O handles.
	#
	def reset_ui
		console.unset_log_source
		console.reset_ui
	end

	#
	# Interacts with the meterpreter client at a user interface level.
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


	##
	#
	# Msf::Session::Comm implementors
	#
	##

	#
	# Creates a connection based on the supplied parameters and returns it to
	# the caller.  The connection is created relative to the remote machine on
	# which the meterpreter server instance is running.
	#
	def create(param)
		case param.proto
			when 'tcp'
				return net.socket.create(param)
			else
				raise Rex::UnsupportedProtocol.new(param.proto), caller
		end
	end

protected

	attr_accessor :rstream, :console # :nodoc:

end

end
end
