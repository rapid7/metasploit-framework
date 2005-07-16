require 'msf/core'
require 'msf/base'
require 'msf/ui'
require 'msf/ui/console/framework_event_manager'
require 'msf/ui/console/command_dispatcher'
require 'msf/ui/console/shell'
require 'msf/ui/console/table'
require 'find'

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

	ConfigGroup = "framework/ui/console"

	#
	# The console driver processes various framework notified events.
	#
	include FrameworkEventManager

	#
	# The console driver is a command shell.
	#
	include Msf::Ui::Console::Shell

	def initialize(prompt = "%umsf", prompt_char = ">%c")
		# Initialize attributes
		self.framework        = Msf::Simple::Framework.create
		self.dispatcher_stack = []

		# Initialize config
		Msf::Config.init

		# Add the core command dispatcher as the root of the dispatcher
		# stack
		enstack_dispatcher(CommandDispatcher::Core)

		# Initialize the super
		super

		# Register event handlers
		register_event_handlers
		
		# Process things before we actually display the prompt and get rocking
		on_startup

		# Load console-specific configuration
		load_config

		# Process the resource script
		process_rc_file
	end

	#
	# Loads configuration for the console
	#
	def load_config
		begin
			conf = Msf::Config.load
		rescue
			wlog("Failed to load configuration: #{$!}")
			return
		end

		# If we have configuration, process it
		if (conf.group?(ConfigGroup))
			conf[ConfigGroup].each_pair { |k, v|
				case k
					when "ActiveModule"
						run_single("use #{v}")
				end
			}
		end
	end

	#
	# Saves configuration for the console
	#
	def save_config
		# Build out the console config group
		group = {}

		if (active_module)
			group['ActiveModule'] = active_module.fullname
		end

		# Save it
		begin 
			Msf::Config.save(
				ConfigGroup => group)
		rescue
			log_error("Failed to save console config: #{$!}")
		end
	end

	#
	# TODO:
	#
	# Processes the resource script file for the console
	#
	def process_rc_file
	end

	#
	# Called before things actually get rolling such that banners can be
	# displayed, scripts can be processed, and other fun can be had.
	#
	def on_startup
		# Prevent output from being displayed for now
		self.disable_output = true

		# Run a few commands to start things off
		run_single("search #{File.join(File.dirname(__FILE__), '..', '..', '..', '..', 'modules')}")

		# Re-enable output
		self.disable_output = false

		# Build the banner message
		run_single("banner")
	end

	#
	# Performs tab completion on shell input if supported
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

	# Run a single command line
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
						eval("
							dispatcher.#{'cmd_' + method}(*arguments)
							found = true")
					end
				rescue
					output.print_error("Error while running command #{method}: #{$!}\n#{$@.join("\n")}\n.")
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
	attr_accessor :active_module

protected

	attr_writer   :dispatcher_stack, :framework

end

end
end
end
