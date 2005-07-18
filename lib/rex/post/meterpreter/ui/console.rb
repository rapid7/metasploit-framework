require 'rex/ui'
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Console
# -------
#
# This class provides a shell driven interface to the meterpreter client API.
#
###
class Console

	include Rex::Ui::Text::DispatcherShell

	# Dispatchers
	require 'rex/post/meterpreter/ui/console/core'

	#
	# Initialize the meterpreter console
	#
	def initialize(client)
		super("%bmeterpreter%c")

		# The meterpreter client context
		self.client = client

		# Point the input/output handles elsewhere
		reset_ui

		enstack_dispatcher(Console::Core)
	end

	#
	# Called when someone wants to interact with the meterpreter client.  It's
	# assumed that init_ui has been called prior.
	#
	def interact(&block)
		run { |line|
			# Run the command
			run_single(line)

			# If a block was supplied, call it, otherwise return false
			if (block)
				block.call
			else
				false
			end
		}
	end

	attr_reader :client

protected
	
	attr_writer :client

end

end
end
end
end
