require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Core
# ----
#
# Core meterpreter client commands.
#
###
class Console::CommandDispatcher::Core

	include Console::CommandDispatcher

	def initialize(shell)
		super

		self.extensions = []
	end

	@@use_opts = Rex::Parser::Arguments.new(
		"-m" => [ true,  "The name of the module or modules to load (Ex: stdapi)." ],
		"-h" => [ false, "Help banner."                                            ])

	#
	# List of supported commands
	#
	def commands
		{
			"?"    => "Help menu",
			"exit" => "Terminate the meterpreter session",
			"help" => "Help menu",
			"use"  => "Load a one or more meterpreter extensions",
			"quit" => "Terminate the meterpreter session",
		}
	end

	#
	# Core baby.
	#
	def name
		"Core"
	end

	#
	# Terminates the meterpreter session
	#
	def cmd_exit(*args)
		shell.stop
	end

	alias cmd_quit cmd_exit

	#
	# Displays the help menu
	#
	def cmd_help(*args)
	end

	#
	# Loads one or more meterpreter extensions
	#
	def cmd_use(*args)
		if (args.length == 0)
			args.unshift("-h")
		end

		modules = nil

		@@use_opts.parse(args) { |opt, idx, val|
			case opt
				when "-m"
					modules = val.split(/,\s?/)
				when "-h"
					print(
						"Usage: use [options]\n\n" +
						"Loads a meterpreter extension module or modules.\n" +
						@use_opts.usage)
					return true
			end
		}

		# Load each of the modules
		modules.each { |m|
			md = m.downcase

			if (extensions.include?(md))
				print_error("The '#{m}' extension has already been loaded.")
				next
			end

			print("Loading extension #{m}...")

			begin
				# Use the remote side, then load the client-side
				if (client.core.use(md) == true)
					add_extension_client(md)
				end
			rescue
				log_error("failure: #{$!}")
				next
			end

			print_line("success.")
		}

		return true
	end

protected

	attr_accessor :extensions

	CommDispatcher = Console::CommandDispatcher

	#
	# Loads the client extension specified in mod
	#
	def add_extension_client(mod)
		clirb  = File.join(Rex::Root, "post/meterpreter/ui/console/command_dispatcher/#{mod}.rb")

		old  = CommDispatcher.constants

		require(clirb)

		new  = CommDispatcher.constants
		diff = new - old

		if (diff.empty? == true)
			print_error("Failed to load client portion of #{mod}.")
			return false
		end

		# Create the dispatcher	
		klass = CommDispatcher.const_get(diff[0])

		# Enstack the dispatcher
		self.shell.enstack_dispatcher(klass)

		# Insert the module into the list of extensions
		self.extensions << mod
	end
end

end
end
end
end
