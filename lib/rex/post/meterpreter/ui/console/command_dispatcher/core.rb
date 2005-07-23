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
		self.ext_hash   = {}
	end

	@@use_opts = Rex::Parser::Arguments.new(
		"-h" => [ false, "Help banner."                                            ])

	#
	# List of supported commands
	#
	def commands
		{
			"?"       => "Help menu",
			"exit"    => "Terminate the meterpreter session",
			"help"    => "Help menu",
			"migrate" => "Migrate the server to another process",
			"use"     => "Load a one or more meterpreter extensions",
			"quit"    => "Terminate the meterpreter session",
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
		print(shell.help_to_s)
	end

	alias cmd_? cmd_help

	#
	# Migrates the server to the supplied process identifier.
	#
	def cmd_migrate(*args)
		if (args.length == 0)
			print_line(
				"Usage: migrate pid\n\n" +
				"Migrates the server instance to another process.\n" +
				"Note: Any open channels or other dynamic state will be lost.")
			return true
		end

		pid = args[0].to_i

		print_status("Migrating to #{pid}...")

		# Do this thang.
		client.core.migrate(pid)

		print_status("Migration completed successfully.")
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
				when "-h"
					print(
						"Usage: use [options]\n\n" +
						"Loads a meterpreter extension module or modules.\n" +
						@use_opts.usage)
					return true
			end
		}

		# Load each of the modules
		args.each { |m|
			md = m.downcase

			if (extensions.include?(md))
				print_error("The '#{md}' extension has already been loaded.")
				next
			end

			print("Loading extension #{md}...")

			begin
				# Use the remote side, then load the client-side
				if (client.core.use(md) == true)
					add_extension_client(md)
				end
			rescue
				log_error("\nfailure: #{$!}")
				next
			end

			print_line("success.")
		}

		return true
	end

protected

	attr_accessor :extensions, :ext_hash

	CommDispatcher = Console::CommandDispatcher

	#
	# Loads the client extension specified in mod
	#
	def add_extension_client(mod)
		clirb  = File.join(Rex::Root, "post/meterpreter/ui/console/command_dispatcher/#{mod}.rb")

		old = CommDispatcher.constants

		if (require(clirb) == true)
			new  = CommDispatcher.constants
			diff = new - old
	
			if (diff.empty? == true)
				print_error("Failed to load client portion of #{mod}.")
				return false
			end

			self.ext_hash[mod] = CommDispatcher.const_get(diff[0])
		end
	
		# Create the dispatcher	
		klass = self.ext_hash[mod]

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
