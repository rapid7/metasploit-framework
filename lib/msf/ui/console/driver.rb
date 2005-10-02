require 'msf/core'
require 'msf/base'
require 'msf/ui'
require 'msf/ui/console/framework_event_manager'
require 'msf/ui/console/command_dispatcher'
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

	ConfigCore  = "framework/core"
	ConfigGroup = "framework/ui/console"

	#
	# The console driver processes various framework notified events.
	#
	include FrameworkEventManager

	#
	# The console driver is a command shell.
	#
	include Rex::Ui::Text::DispatcherShell

	def initialize(prompt = "%umsf", prompt_char = ">%c")
		# Call the parent
		super

		# Initialize attributes
		self.framework = Msf::Simple::Framework.create

		# Add the core command dispatcher as the root of the dispatcher
		# stack
		enstack_dispatcher(CommandDispatcher::Core)

		# Register event handlers
		register_event_handlers

		# Temporarily disable output
		self.disable_output = true

		# Load console-specific configuration
		load_config
	
		# Re-enable output
		self.disable_output = false

		# Process things before we actually display the prompt and get rocking
		on_startup

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
				case k.downcase
					when "activemodule"
						run_single("use #{v}")
				end
			}
		end

		if (conf.group?(ConfigCore))
			conf[ConfigCore].each_pair { |k, v|
				case k.downcase
					when "sessionlogging"
						handle_session_logging(v)
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
		# Recalculate tab completion
		run_single("_recalculate_tc")

		# Build the banner message
		run_single("banner")
	end

	#
	# Called when a variable is set to a specific value.  This allows the
	# console to do extra processing, such as enabling logging or doing
	# some other kind of task.  If this routine returns false it will indicate
	# that the variable is not being set to a valid value.
	#
	def on_variable_set(glob, var, val)
		case var.downcase
			when "payload"
				if (framework.modules.valid?(val) == false)
					return false
				end
			when "sessionlogging"
				handle_session_logging(val) if (glob)
		end
	end

	#
	# Called when a variable is unset.  If this routine returns false it is an
	# indication that the variable should not be allowed to be unset.
	#
	def on_variable_unset(glob, var)
		case var.downcase
			when "sessionlogging"
				handle_session_logging('0') if (glob)
		end
	end

	attr_reader   :framework
	attr_accessor :active_module

protected

	attr_writer   :framework
	
	##
	#
	# Handlers for various global configuration values
	#
	##

	#
	# SessionLogging
	#
	def handle_session_logging(val)
		if (val =~ /^(yes|y|true|t|1)/i)
			Msf::Logging.enable_session_logging(true)
			print_line("Session logging will be enabled for future sessions.")
		else
			Msf::Logging.enable_session_logging(false)
			print_line("Session logging will be disabled for future sessions.")
		end
	end
end

end
end
end
