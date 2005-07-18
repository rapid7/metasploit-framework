module Msf
module Ui
module Console

module CommandDispatcher

	include Rex::Ui::Text::DispatcherShell::CommandDispatcher

	def initialize(driver)
		super

		self.driver = driver
	end

	def framework
		return driver.framework
	end

	def active_module
		driver.active_module
	end

	def active_module=(mod)
		driver.active_module = mod
	end

	def log_error(err)
		print_error(err)

		wlog(err)
		dlog("Call stack:\n#{$@.join("\n")}", 'core', LEV_1)
	end

	attr_accessor :driver

end 

module ModuleCommandDispatcher

	include Msf::Ui::Console::CommandDispatcher

	def mod
		return driver.active_module
	end

end

end end end
	
require 'msf/ui/console/command_dispatcher/core'

