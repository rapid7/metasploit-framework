require 'rex/ui'

module Rex
module Ui
module Text

###
#
# The dispatcher shell class is designed to provide a generic means
# of processing various shell commands that may be located in
# different modules or chunks of codes.  These chunks are referred
# to as command dispatchers.  The only requirement for command dispatchers is
# that they prefix every method that they wish to be mirrored as a command
# with the cmd_ prefix.
#
###
module DispatcherShell

	###
	#
	# Empty template base class for command dispatchers.
	#
	###
	module CommandDispatcher

		#
		# Initializes the command dispatcher mixin.
		#
		def initialize(shell)
			self.shell = shell
			self.tab_complete_items = []
		end

		#
		# Returns nil for an empty set of commands.
		#
		def commands
		end
	
		#
		# Wrapps shell.print_error
		#
		def print_error(msg = '')
			shell.print_error(msg)
		end

		#
		# Wrapps shell.print_status
		#
		def print_status(msg = '')
			shell.print_status(msg)
		end

		#
		# Wrapps shell.print_line
		#
		def print_line(msg = '')
			shell.print_line(msg)
		end

		#
		# Wrapps shell.print
		#
		def print(msg = '')
			shell.print(msg)
		end

		#
		# Wraps shell.update_prompt
		#
		def update_prompt(prompt)
			shell.update_prompt(prompt)
		end

		#
		# No tab completion items by default
		#
		attr_accessor :shell, :tab_complete_items

	end

	#
	# DispatcherShell derives from shell.
	#
	include Shell

	#
	# Initialize the dispatcher shell.
	#
	def initialize(prompt, prompt_char = '>')
		super

		self.dispatcher_stack = []
	end

	#
	# Performs tab completion on shell input if supported.
	#
	def tab_complete(str)
		items = []

		# Next, try to match internal command or value completion
		# Enumerate each entry in the dispatcher stack
		dispatcher_stack.each { |dispatcher|
			# If it supports commands, query them all
			if (dispatcher.respond_to?('commands'))
				items.concat(dispatcher.commands.to_a.map { |x| x[0] })
			end

			# If the dispatcher has custom tab completion items, use them
			items.concat(dispatcher.tab_complete_items || [])
		}

		items.find_all { |e| 
			e =~ /^#{str}/
		}
	end

	#
	# Run a single command line.
	#
	def run_single(line)
		arguments = parse_line(line)
		method    = arguments.shift
		found     = false

		reset_color if (supports_color?)

		if (method)
			entries = dispatcher_stack.length

			dispatcher_stack.each { |dispatcher|
				begin
					if (dispatcher.respond_to?('cmd_' + method))
						run_command(dispatcher, method, arguments)

						found = true
					end
				rescue
					output.print_error(
						"Error while running command #{method}: #{$!}" +
						"\n\nCall stack:\n#{$@.join("\n")}")
				end

				# If the dispatcher stack changed as a result of this command,
				# break out
				break if (dispatcher_stack.length != entries)
			}

			if (found == false)
				unknown_command(method, line)
			end
		end

		return found
	end

	#
	# Runs the supplied command on the given dispatcher.
	#
	def run_command(dispatcher, method, arguments)
		eval("dispatcher.#{'cmd_' + method}(*arguments)")
	end

	#
	# If the command is unknown...
	#
	def unknown_command(method, line)
		output.print_error("Unknown command: #{method}.")
	end

	#
	# Push a dispatcher to the front of the stack.
	#
	def enstack_dispatcher(dispatcher)
		self.dispatcher_stack.unshift(inst = dispatcher.new(self))

		inst
	end

	#
	# Pop a dispatcher from the front of the stacker.
	#
	def destack_dispatcher
		self.dispatcher_stack.shift
	end

	#
	# Adds the supplied dispatcher to the end of the dispatcher stack so that
	# it doesn't affect any enstack'd dispatchers.
	#
	def append_dispatcher(dispatcher)
		self.dispatcher_stack.push(inst = dispatcher.new(self))

		inst
	end

	#
	# Removes the supplied dispatcher instance.
	#
	def remove_dispatcher(name)
		self.dispatcher_stack.delete_if { |inst|
			(inst.name == name)
		}
	end

	#
	# Returns the current active dispatcher
	#
	def current_dispatcher
		self.dispatcher_stack[0]
	end

	#
	# Return a readable version of a help banner for all of the enstacked
	# dispatchers.
	#
	def help_to_s(opts = {})
		str = ''

		dispatcher_stack.reverse.each { |dispatcher|
			# No commands?  Suckage.
			next if ((dispatcher.respond_to?('commands') == false) or
			         (dispatcher.commands == nil) or
			         (dispatcher.commands.length == 0))

			# Display the commands
			tbl = Table.new(
				'Header'  => "#{dispatcher.name} Commands",
				'Indent'  => opts['Indent'] || 4,
				'Columns' => 
					[
						'Command',
						'Description'
					],
				'ColProps' =>
					{
						'Command' =>
							{
								'MaxWidth' => 12
							}
					})

			dispatcher.commands.sort.each { |c|
				tbl << c
			}

			str += "\n" + tbl.to_s + "\n"
		}

		return str
	end


	attr_accessor :dispatcher_stack # :nodoc:

end

end
end
end
