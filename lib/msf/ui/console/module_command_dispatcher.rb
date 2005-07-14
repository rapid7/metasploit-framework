module Msf
module Ui
module Console

module ModuleCommandDispatcher

	include Msf::Ui::Console::CommandDispatcher

	def mod
		return driver.active_module
	end

end

end end end
