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

	def set_active_module(mod)
		driver.datastore['_ActiveModule'] = mod
	end

	def get_active_module
		return driver.datastore['_ActiveModule']
	end

	#
	# No tab completion items by default
	#
	attr_accessor :tab_complete_items

protected

	attr_accessor :driver

end 

end end end

require 'msf/ui/console/module_command_dispatcher'
require 'msf/ui/console/command_dispatcher/core'
