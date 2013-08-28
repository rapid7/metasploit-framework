# -*- coding: binary -*-
require 'rex/ui'
require 'pp'
require 'csv'

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
		# This method should be overridden to return a Hash with command
		# names for keys and brief help text for values.
		#
		def commands
		end

		#
		# Returns an empty set of commands.
		#
		# This method should be overridden if the dispatcher has commands that
		# should be treated as deprecated. Deprecated commands will not show up in
		# help and will not tab-complete, but will still be callable.
		#
		def deprecated_commands
			[]
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
		# Wraps shell.print_good
		#
		def print_good(msg = '')
			shell.print_good(msg)
		end

		#
		# Wraps shell.print_warning
		#
		def print_warning(msg = '')
			shell.print_warning(msg)
		end

		#
		# Wraps shell.print
		#
		def print(msg = '')
			shell.print(msg)
		end

		#
		# Print a warning that the called command is deprecated and optionally
		# forward to the replacement +method+ (useful for when commands are
		# renamed).
		#
		def deprecated_cmd(method=nil, *args)
			cmd = caller[0].match(/`cmd_(.*)'/)[1]
			print_error "The #{cmd} command is DEPRECATED"
			if cmd == "db_autopwn"
				print_error "See http://r-7.co/xY65Zr instead"
			elsif method and self.respond_to?("cmd_#{method}")
				print_error "Use #{method} instead"
				self.send("cmd_#{method}", *args)
			end
		end

		def deprecated_help(method=nil)
			cmd = caller[0].match(/`cmd_(.*)_help'/)[1]
			print_error "The #{cmd} command is DEPRECATED"
			if cmd == "db_autopwn"
				print_error "See http://r-7.co/xY65Zr instead"
			elsif method and self.respond_to?("cmd_#{method}_help")
				print_error "Use 'help #{method}' instead"
				self.send("cmd_#{method}_help")
			end
		end

		#
		# Wraps shell.update_prompt
		#
		def update_prompt(prompt=nil, prompt_char = nil, mode = false)
			shell.update_prompt(prompt, prompt_char, mode)
		end

		def cmd_help_help
			print_line "There's only so much I can do"
		end

		#
		# Displays the help banner.  With no arguments, this is just a list of
		# all commands grouped by dispatcher.  Otherwise, tries to use a method
		# named cmd_#{+cmd+}_help for the first dispatcher that has a command
		# named +cmd+.  If no such method exists, uses +cmd+ as a regex to
		# compare against each enstacked dispatcher's name and dumps commands
		# of any that match.
		#
		def cmd_help(cmd=nil, *ignored)
			if cmd
				help_found = false
				cmd_found = false
				shell.dispatcher_stack.each do |dispatcher|
					next unless dispatcher.respond_to?(:commands)
					next if (dispatcher.commands.nil?)
					next if (dispatcher.commands.length == 0)

					if dispatcher.respond_to?("cmd_#{cmd}")
						cmd_found = true
						break unless dispatcher.respond_to? "cmd_#{cmd}_help"
						dispatcher.send("cmd_#{cmd}_help")
						help_found = true
						break
					end
				end

				unless cmd_found
					# We didn't find a cmd, try it as a dispatcher name
					shell.dispatcher_stack.each do |dispatcher|
						if dispatcher.name =~ /#{cmd}/i
							print_line(dispatcher.help_to_s)
							cmd_found = help_found = true
						end
					end
				end
				print_error("No help for #{cmd}, try -h") if cmd_found and not help_found
				print_error("No such command") if not cmd_found
			else
				print(shell.help_to_s)
			end
		end

		#
		# Tab completion for the help command
		#
		# By default just returns a list of all commands in all dispatchers.
		#
		def cmd_help_tabs(str, words)
			return [] if words.length > 1

			tabs = []
			shell.dispatcher_stack.each { |dispatcher|
				tabs += dispatcher.commands.keys
			}
			return tabs
		end

		alias cmd_? cmd_help

		#
		# Return a pretty, user-readable table of commands provided by this
		# dispatcher.
		#
		def help_to_s(opts={})
			# If this dispatcher has no commands, we can't do anything useful.
			return "" if commands.nil? or commands.length == 0

			# Display the commands
			tbl = Table.new(
				'Header'  => "#{self.name} Commands",
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

			commands.sort.each { |c|
				tbl << c
			}

			return "\n" + tbl.to_s + "\n"
		end

		#
		# No tab completion items by default
		#
		attr_accessor :shell, :tab_complete_items

		#
		# Provide a generic tab completion for file names.
		#
		# If the only completion is a directory, this descends into that directory
		# and continues completions with filenames contained within.
		#
		def tab_complete_filenames(str, words)
			matches = ::Readline::FILENAME_COMPLETION_PROC.call(str)
			if matches and matches.length == 1 and File.directory?(matches[0])
				dir = matches[0]
				dir += File::SEPARATOR if dir[-1,1] != File::SEPARATOR
				matches = ::Readline::FILENAME_COMPLETION_PROC.call(dir)
			end
			matches
		end

	end

	#
	# DispatcherShell derives from shell.
	#
	include Shell

	#
	# Initialize the dispatcher shell.
	#
	def initialize(prompt, prompt_char = '>', histfile = nil, framework = nil)
		super

		# Initialze the dispatcher array
		self.dispatcher_stack = []

		# Initialize the tab completion array
		self.tab_words = []
		self.on_command_proc = nil
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
				items.concat(dispatcher.commands.keys)
			end

			# If the dispatcher exports a tab completion function, use it
			if(dispatcher.respond_to?('tab_complete_helper'))
				res = dispatcher.tab_complete_helper(str, tab_words)
			else
				res = tab_complete_helper(dispatcher, str, tab_words)
			end

			if (res.nil?)
				# A nil response indicates no optional arguments
				return [''] if items.empty?
			else
				# Otherwise we add the completion items to the list
				items.concat(res)
			end
		}

		# Verify that our search string is a valid regex
		begin
			Regexp.compile(str)
		rescue RegexpError
			str = Regexp.escape(str)
		end

		# @todo - This still doesn't fix some Regexp warnings:
		# ./lib/rex/ui/text/dispatcher_shell.rb:171: warning: regexp has `]' without escape

		# Match based on the partial word
		items.find_all { |e|
			e =~ /^#{str}/
		# Prepend the rest of the command (or it all gets replaced!)
		}.map { |e|
			tab_words.dup.push(e).join(' ')
		}
	end

	#
	# Provide command-specific tab completion
	#
	def tab_complete_helper(dispatcher, str, words)
		items = []

		tabs_meth = "cmd_#{words[0]}_tabs"
		# Is the user trying to tab complete one of our commands?
		if (dispatcher.commands.include?(words[0]) and dispatcher.respond_to?(tabs_meth))
			res = dispatcher.send(tabs_meth, str, words)
			return [] if res.nil?
			items.concat(res)
		else
			# Avoid the default completion list for known commands
			return []
		end

		return items
	end

	#
	# Run multiple commands from one input line
	#
	# @see CSV#new Line is parsed with native Ruby CSV parser using ';' as the separator
	# @note The CSV parser essentially escapes an entire field when it is surrounded by the quote char
	#   It's very similar to quoting an entire file path if it contains a space vs only escaping the
	#   space in the file path using a single escape character.  Addtionally Ruby itself requires
	#   one to escape an unmatched single or double quote and shell requires one to escape commands
	#   containing spaces which can lead to complex cases depending on the command sep and quoting
	#   char used, therefore pre-processed +line+ examples are worth providing
	# 	Msfconsole example, simple case, multiple commands and no escaping required
	#     set RHOST 1.1.1.1;set LHOST 1.1.1.2
	#   Msfconsole example, scaping (quoting) one or more instances of the command separator
	#     "set SMBUser f;oo;bar";"set SMBPass fu;bar";set LPORT 443
	#   Msfconsole example, escaping (quoting) command sep while Ruby escaping unmatched single quote
	#     "set SMBPass foo\';bar";set LPORT 443
	#   Msfconsole example, escaping (quoting) the command separator and the quoting character
	#     "set SMBPass foo\"";bar";set LPORT 443
	# 	Shell example, escaping multiline command when one cmd contains the cmd separator
	#     msfconsole -x 'set SMBUser admin;"set SMBPass foo;bar"'
	# @see https://gist.github.com/kernelsmith/5822064 for full examples and elaboration
	# @param line [String] The data to be parsed
	# @param separator [String] The separator used to delimit the data
	# @param quote_char [String] The quoting escape character (1 char only) used to escape +separator+
	# @return [true] if all commands succeeded
	# @return [false] otherwise
	def run_multiple(line, separator = ';', quote_char = '"')
		lines = []
		# handle a multi-command line (lines with cmd;other_cmd)
		opts = {:col_sep => separator, :quote_char => quote_char}
		lines = parse_multi_line(line, opts)
		all_commands_found = true
		if lines.empty?
			print_error "No parsable commands were found."
			return false
		end
		lines.each do |l|
			# run each single command
			all_commands_found = false if not run_single(l)
		end
		return all_commands_found
	end

	def parse_multi_line(line, parse_opts = {})
		line.gsub!(/(\r|\n)/, '') # the CSV parser can handle these, but there's no point
		parse_defaults = {
							# @todo, make these values definable via advanced options
							:col_sep          => ';',
							:quote_char       => '"',
							:skip_blanks      => true,
							:field_size_limit => 1024, # this effectively sets quoted command size limit
							# after field_size_limit, if a matching quote_char isn't found then
							# a CSV::MalformedCSVError is raised
						}
		# supply default parse options for those that have not been defined
		parse_opts = parse_defaults.merge(parse_opts)
		begin
			return CSV.parse(line, parse_opts).first
		rescue CSV::MalformedCSVError => e
			print_error "Illegal quoting.  Use 2 consecutive instances of the quote char to escape it."
			return []
		end
		# CSV.parse will return an Array of Rows (which are Arrays when no headers are used), and since
		# we removed new lines, we always have an Array of 1 Array, so we send :first method above
	end

	#
	# Run a single command provided in +line+
	#
	# @param line [String] The command line containing only one command
	# @return [Boolean] Returns true if the command succeeds, otherwise false
	def run_single(line)
		arguments = parse_line(line)
		method    = arguments.shift
		found     = false
		error     = false

		# If output is disabled output will be nil
		output.reset_color if (output)

		if (method)
			entries = dispatcher_stack.length

			dispatcher_stack.each { |dispatcher|
				next if not dispatcher.respond_to?('commands')

				begin
					if (dispatcher.commands.has_key?(method) or dispatcher.deprecated_commands.include?(method))
						self.on_command_proc.call(line.strip) if self.on_command_proc
						run_command(dispatcher, method, arguments)
						found = true
					end
				rescue
					error = $!

					print_error(
						"Error while running command #{method}: #{$!}" +
						"\n\nCall stack:\n#{$@.join("\n")}")
				rescue ::Exception
					error = $!

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
		inst = dispatcher.new(self)
		self.dispatcher_stack.each { |disp|
			if (disp.name == inst.name)
				raise RuntimeError.new("Attempting to load already loaded dispatcher #{disp.name}")
			end
		}
		self.dispatcher_stack.push(inst)

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
	# See +CommandDispatcher#help_to_s+
	#
	def help_to_s(opts = {})
		str = ''

		dispatcher_stack.reverse.each { |dispatcher|
			str << dispatcher.help_to_s
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
