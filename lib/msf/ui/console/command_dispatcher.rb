module Msf
module Ui
module Console

module CommandDispatcher

	def initialize(in_driver)
		self.driver = in_driver
		self.tab_complete_items = []
	end

	def print_error(msg = '')
		driver.print_error(msg)
	end

	def print_status(msg = '')
		driver.print_status(msg)
	end

	def print_line(msg = '')
		driver.print_line(msg)
	end

	def print(msg = '')
		driver.print(msg)
	end

	def update_prompt(prompt)
		driver.update_prompt(prompt)
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

	#
	# No tab completion items by default
	#
	attr_accessor :tab_complete_items

protected

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

