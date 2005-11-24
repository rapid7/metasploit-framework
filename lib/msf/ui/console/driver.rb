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

	#
	# Initializes a console driver instance with the supplied prompt string and
	# prompt character.
	#
	def initialize(prompt = "%umsf", prompt_char = ">%c")
		# Call the parent
		super

		# Temporarily disable output
		self.disable_output = true

		# Load pre-configuration
		load_preconfig
	
		# Initialize attributes
		self.framework = Msf::Simple::Framework.create

		# Add the core command dispatcher as the root of the dispatcher
		# stack
		enstack_dispatcher(CommandDispatcher::Core)

		# Register event handlers
		register_event_handlers

		# Load console-specific configuration
		load_config
	
		# Re-enable output
		self.disable_output = false

		# Process things before we actually display the prompt and get rocking
		on_startup

		# Process the resource script
		process_rc_file
		
		# Initialize the tab completion array
		self.tab_words = []
	end

	#
	# Loads configuration that needs to be analyzed before the framework
	# instance is created.
	#
	def load_preconfig
		begin
			conf = Msf::Config.load
		rescue
			wlog("Failed to load configuration: #{$!}")
			return
		end

		if (conf.group?(ConfigCore))
			conf[ConfigCore].each_pair { |k, v|
				on_variable_set(true, k, v)
			}
		end
	end

	#
	# Loads configuration for the console.
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
	end

	#
	# Saves configuration for the console.
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
	# Processes the resource script file for the console.
	#
	def process_rc_file
	end

	#
	# Called before things actually get rolling such that banners can be
	# displayed, scripts can be processed, and other fun can be had.
	#
	def on_startup
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
				
				if (framework and framework.modules.valid?(val) == false)
					return false
				end
			when "sessionlogging"
				handle_session_logging(val) if (glob)
			when "consolelogging"
				handle_console_logging(val) if (glob)
			when "evasion"
				handle_evasion(val) if (glob)
			when "loglevel"
				handle_loglevel(val) if (glob)
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
			when "consolelogging"
				handle_console_logging('0') if (glob)
			when "evasion"
				handle_evasion(EVASION_NORMAL) if (glob)
			when "loglevel"
				handle_loglevel(nil) if (glob)
		end
	end

	#
	# The framework instance associated with this driver.
	#
	attr_reader   :framework
	#
	# The active module associated with the driver.
	#
	attr_accessor :active_module

protected

	attr_writer   :framework # :nodoc:
	attr_accessor :tab_words # :nodoc:
	
	##
	#
	# Handlers for various global configuration values
	#
	##

	#
	# SessionLogging.
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
	
	#
	# ConsoleLogging.
	#
	def handle_console_logging(val)
		if (val =~ /^(yes|y|true|t|1)/i)
			Msf::Logging.enable_log_source('console')
			print_line("Console logging is now enabled.")

			set_log_source('console')
			
			rlog("\n[*] Console logging started: #{Time.now}\n\n", 'console')
		else
			rlog("\n[*] Console logging stopped: #{Time.now}\n\n", 'console')

			unset_log_source

			Msf::Logging.disable_log_source('console')
			print_line("Console logging is now disabled.")
		end
	end

	#
	# Evasion.  Sets the global evasion level based on the supplied argument.
	#
	def handle_evasion(val)
		if (val =~ /^(normal|low|high)$/i)
			Rex::Evasion.set_level(val.downcase)
		else
			false
		end
	end

	#
	# This method handles adjusting the global log level threshold.
	#
	def handle_loglevel(val)
		set_log_level(Rex::LogSource, val)
		set_log_level(Msf::LogSource, val)
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
		
		# Pop the last word and pass it to the parent
		super(self.tab_words.pop)
	end

end

end
end
end
