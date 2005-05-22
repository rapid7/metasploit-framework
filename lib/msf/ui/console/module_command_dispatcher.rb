module Msf
module Ui
module Console

module ModuleCommandDispatcher

	include Msf::Ui::Console::CommandDispatcher

	def mod
		return get_active_module
	end

end

end end end
