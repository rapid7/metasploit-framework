module Msf
module Sessions
	autoload :CommandShell,        'msf/base/sessions/command_shell'
	autoload :CommandShellWindows, 'msf/base/sessions/command_shell'
	autoload :CommandShellUnix,    'msf/base/sessions/command_shell'

	autoload :Meterpreter,           'msf/base/sessions/meterpreter'
	autoload :Meterpreter_Java_Java, 'msf/base/sessions/meterpreter_java'
	autoload :Meterpreter_Php_Php,   'msf/base/sessions/meterpreter_php'
	autoload :Meterpreter_x64_Win,   'msf/base/sessions/meterpreter_x64_win'
	autoload :Meterpreter_x86_BSD,   'msf/base/sessions/meterpreter_x86_bsd'
	autoload :Meterpreter_x86_Linux, 'msf/base/sessions/meterpreter_x86_linux'
	autoload :Meterpreter_x86_Win,   'msf/base/sessions/meterpreter_x86_win'

	autoload :VncInject, 'msf/base/sessions/vncinject'

	autoload :TTY, 'msf/base/sessions/tty'
end
end
