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
	require 'rex/post/meterpreter/ui/console/interactive_channel'
	require 'rex/post/meterpreter/ui/console/command_dispatcher'
	require 'rex/post/meterpreter/ui/console/command_dispatcher/core'

	#
	# Initialize the meterpreter console
	#
	def initialize(client)
		super("%umeterpreter%c")

		# The meterpreter client context
		self.client = client

		# Point the input/output handles elsewhere
		reset_ui

		enstack_dispatcher(Console::CommandDispatcher::Core)
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

	#
	# Interacts with the supplied channel
	#
	def interact_with_channel(channel)
		channel.extend(InteractiveChannel) unless (channel.kind_of?(InteractiveChannel) == true)

		channel.init_ui(input, output)
		channel.interact
		channel.reset_ui
	end

	#
	# Runs the specified command wrapper in something to catch meterpreter
	# exceptions.
	#
	def run_command(dispatcher, method, arguments)
		begin
			super
		rescue TimeoutError
			output.print_error("Operation timed out.")
		rescue RequestError => info
			output.print_error(info.to_s)
		rescue
			output.print_error("Error running command #{method}: #{$!}")
		end
	end

	attr_reader :client

protected
	
	attr_writer :client

end

end
end
end
end
