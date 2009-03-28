module Msf
module Ui
module Console

###
#
# The common command dispatcher base class that is shared for component-specific
# command dispatching.
#
###
module CommandDispatcher

	include Rex::Ui::Text::DispatcherShell::CommandDispatcher

	#
	# Initializes a command dispatcher instance.
	#
	def initialize(driver)
		super

		self.driver = driver
	end

	#
	# Returns the framework instance associated with this command dispatcher.
	#
	def framework
		return driver.framework
	end

	#
	# Returns the active module if one has been selected, otherwise nil is
	# returned.
	#
	def active_module
		driver.active_module
	end

	#
	# Sets the active module for this driver instance.
	#
	def active_module=(mod)
		driver.active_module = mod
	end

	#
	# Returns the active session if one has been selected, otherwise nil is
	# returned.
	#
	def active_session
		driver.active_session
	end

	#
	# Sets the active session for this driver instance.
	#
	def active_session=(mod)
		driver.active_session = mod
	end
	#
	# Checks to see if the driver is defanged.
	#
	def defanged?
		driver.defanged?
	end

	#
	# Logs an error message to the screen and the log file.  The callstack is
	# also printed.
	#
	def log_error(err)
		print_error(err)

		wlog(err)

		# If it's a syntax error, log the call stack that it originated from.
		dlog("Call stack:\n#{$@.join("\n")}", 'core', LEV_1)
	end

	#
	# Provide command-specific tab completion
	#
	def tab_complete_helper(str, words)
		items = []

		# Is the user trying to tab complete one of our commands?
		if (commands.include?(words[0]))
			if (self.respond_to?('cmd_'+words[0]+'_tabs')) 
				res = self.send('cmd_'+words[0]+'_tabs', str, words)
				return nil if res.nil?
				items.concat(res)
			else
				# Avoid the default completion list for known commands
				return nil
			end
		end

		return items
	end
		
	#
	# The driver that this command dispatcher is associated with.
	#
	attr_accessor :driver
	
end 

###
#
# Module-specific command dispatcher.
#
###
module ModuleCommandDispatcher

	include Msf::Ui::Console::CommandDispatcher

	#
	# The active driver module, if any.
	#
	def mod
		return driver.active_module
	end

	#
	# Sets the active driver module.
	#
	def mod=(m)
		self.driver.active_module = m
	end

end

end end end
	
require 'msf/ui/console/command_dispatcher/core'
