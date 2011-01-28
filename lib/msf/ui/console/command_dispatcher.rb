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
		self.driver.on_command_proc = Proc.new { |command| framework.events.on_ui_command(command) }
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

	def commands
		{ "reload" => "Reload the current module from disk" }
	end

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

	#
	# Reloads the active module
	#
	def cmd_reload(*args)
		begin
			reload
		rescue
			log_error("Failed to reload: #{$!}")
		end
	end

	def cmd_reload_help
		print_line "Usage: reload [-k]"
		print_line
		print_line "Reloads the current module."
		print @@reload_opts.usage
	end

	#
	# Reload the current module, optionally stopping existing job
	#
	def reload(should_stop_job=false)
		if should_stop_job and mod.job_id
			print_status('Stopping existing job...')

			framework.jobs.stop_job(mod.job_id)
			mod.job_id = nil
		end

		print_status('Reloading module...')

		omod = self.mod
		self.mod = framework.modules.reload_module(mod)

		if(not self.mod)
			print_status("Failed to reload module: #{framework.modules.failed[omod.file_path]}")
			self.mod = omod
			return
		end

		self.mod.init_ui(driver.input, driver.output)
		mod
	end

end

end end end
	
require 'msf/ui/console/command_dispatcher/core'
