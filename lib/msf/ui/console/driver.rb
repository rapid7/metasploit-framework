require 'msf/core'
require 'msf/base'
require 'msf/ui'
require 'msf/ui/console/shell'
require 'msf/ui/console/command_dispatcher'

require 'msf/ui/console/table'

module Msf
module Ui
module Console


###
#
# Driver
# ------
#
# This class implements a user interface driver on a console interface.
#
###
class Driver < Msf::Ui::Driver

	include Msf::Ui::Console::Shell

	def initialize(prompt = "msf")
		# Initialize attributes
		self.framework        = Msf::Framework.new
		self.dispatcher_stack = []

		# Add the core command dispatcher as the root of the dispatcher
		# stack
		enstack_dispatcher(CommandDispatcher::Core)

		# Initialize the super
		super(prompt)
	end

	# Run a single command line
	def run_single(line)
		arguments = parse_line(line)
		method    = arguments.shift
		found     = false

		if (method)
			entries = dispatcher_stack.length

			dispatcher_stack.each { |dispatcher|
				begin
					eval("
						if (dispatcher.respond_to?('cmd_' + method))
							dispatcher.#{'cmd_' + method}(arguments)
							found = true
						end")
				rescue
					output.print_error("Error while running command #{method}: #{$!}.")
				end

				# If the dispatcher stack changed as a result of this command,
				# break out
				break if (dispatcher_stack.length != entries)
			}

			if (!found)
				output.print_error("Unknown command: #{method}.")
			end
		end

		return found
	end

	# Push a dispatcher to the front of the stack
	def enstack_dispatcher(dispatcher)
		self.dispatcher_stack.unshift(dispatcher.new(self))
	end

	# Pop a dispatcher from the front of the stacker
	def destack_dispatcher
		self.dispatcher_stack.shift
	end

	attr_reader   :dispatcher_stack, :framework

protected

	attr_writer   :dispatcher_stack, :framework

end

end
end
end
