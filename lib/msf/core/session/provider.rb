module Msf
module Session
module Provider
	autoload :SingleCommandExecution, 'msf/core/session/provider/single_command_execution'
	autoload :MultiCommandExecution,  'msf/core/session/provider/multi_command_execution'
	autoload :SingleCommandShell,     'msf/core/session/provider/single_command_shell'
	autoload :MultiCommandShell,      'msf/core/session/provider/multi_command_shell'
end
end
end
