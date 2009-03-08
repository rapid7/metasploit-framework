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
		# Wraps shell.print_error
		#
		def print_error(msg = '')
			shell.print_error(msg)
		end

		#
		# Wraps shell.print_status
		#
		def print_status(msg = '')
			shell.print_status(msg)
		end

		#
		# Wraps shell.print_line
		#
		def print_line(msg = '')
			shell.print_line(msg)
		end

		#
		# Wraps shell.print
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

		# Initialze the dispatcher array
		self.dispatcher_stack = []
		
		# Initialize the tab completion array
		self.tab_words = []		
	end

	#
	# This method accepts the entire line of text from the Readline
	# routine, stores all completed words, and passes the partial
	# word to the real tab completion function. This works around
	# a design problem in the Readline module and depends on the
	# Readline.basic_word_break_characters variable being set to \x00
	#
	def tab_complete(str)
		# Check trailing whitespace so we can tell 'x' from 'x '
		str_match = str.match(/\s+$/)
		str_trail = (str_match.nil?) ? '' : str_match[0]
		
		# Split the line up by whitespace into words
		str_words = str.split(/[\s\t\n]+/)
		
		# Append an empty word if we had trailing whitespace
		str_words << '' if str_trail.length > 0
		
		# Place the word list into an instance variable
		self.tab_words = str_words
		
		# Pop the last word and pass it to the real method
		tab_complete_stub(self.tab_words.pop)
	end

	# Performs tab completion of a command, if supported	
	# Current words can be found in self.tab_words
	#
	def tab_complete_stub(str)
		items = []
		
		return nil if not str
	
		# puts "Words(#{tab_words.join(", ")}) Partial='#{str}'"
		
		# Next, try to match internal command or value completion
		# Enumerate each entry in the dispatcher stack
		dispatcher_stack.each { |dispatcher|
		
			# If no command is set and it supports commands, add them all
			if (tab_words.empty? and dispatcher.respond_to?('commands'))
				items.concat(dispatcher.commands.to_a.map { |x| x[0] })
			end

			# If the dispatcher exports a tab completion function, use it
			if(dispatcher.respond_to?('tab_complete_helper'))
				res = dispatcher.tab_complete_helper(str, tab_words)

				if (res.nil?)
					# A nil response indicates no optional arguments
					return [''] if items.empty?
				else
					# Otherwise we add the completion items to the list
					items.concat(res)
				end
			end
		}

		# Verify that our search string is a valid regex
		begin
			Regexp.compile(str)
		rescue RegexpError => e
			str = Regexp.escape(str)
		end
		
		# XXX - This still doesn't fix some Regexp warnings:
		# ./lib/rex/ui/text/dispatcher_shell.rb:171: warning: regexp has `]' without escape

		# Match based on the partial word
		items.find_all { |e| 
			e =~ /^#{str}/
		# Prepend the rest of the command (or it gets replaced!)
		}.map { |e| 
			tab_words.dup.push(e).join(' ')
		}
	end

	#
	# Run a single command line.
	#
	def run_single(line)
		arguments = parse_line(line)
		method    = arguments.shift
		found     = false
		error     = false

		reset_color if (supports_color?)

		if (method)
			entries = dispatcher_stack.length

			dispatcher_stack.each { |dispatcher|
				next if not dispatcher.respond_to?('commands')

				begin
					if (dispatcher.commands.has_key?(method))
						run_command(dispatcher, method, arguments)
						found = true
					end
				rescue 
					error = true

					print_error(
						"Error while running command #{method}: #{$!}" +
						"\n\nCall stack:\n#{$@.join("\n")}")
				rescue ::Exception
					error = true

					print_error(
						"Error while running command #{method}: #{$!}")
				end

				# If the dispatcher stack changed as a result of this command,
				# break out
				break if (dispatcher_stack.length != entries)
			}

			if (found == false and error == false)
				unknown_command(method, line)
			end
		end

		return found
	end

	#
	# Runs the supplied command on the given dispatcher.
	#
	def run_command(dispatcher, method, arguments)
		self.busy = true
		
		if(blocked_command?(method))
			print_error("The #{method} command has been disabled.")
		else
			dispatcher.send('cmd_' + method, *arguments)
		end
		self.busy = false
	end

	#
	# If the command is unknown...
	#
	def unknown_command(method, line)
		print_error("Unknown command: #{method}.")
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

			str << "\n" + tbl.to_s + "\n"
		}

		return str
	end


		
	#
	# Returns nil for an empty set of blocked commands.
	#
	def blocked_command?(cmd)
		return false if not self.blocked
		self.blocked.has_key?(cmd)
	end

	#
	# Block a specific command
	#
	def block_command(cmd)
		self.blocked ||= {}
		self.blocked[cmd] = true
	end

	#
	# Unblock a specific command
	#
	def unblock_command(cmd)
		self.blocked || return
		self.blocked.delete(cmd)
	end
	

	attr_accessor :dispatcher_stack # :nodoc:
	attr_accessor :tab_words # :nodoc:
	attr_accessor :busy # :nodoc:
	attr_accessor :blocked # :nodoc:

end

end
end
end
