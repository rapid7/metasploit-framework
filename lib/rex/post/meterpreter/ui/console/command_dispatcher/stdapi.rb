require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Stdapi
# ------
#
# Standard API extension.
#
###
class Console::CommandDispatcher::Stdapi

	Klass = Console::CommandDispatcher::Stdapi

	include Console::CommandDispatcher

	require 'rex/post/meterpreter/ui/console/command_dispatcher/stdapi/fs'

	def initialize(shell)
		super

		shell.enstack_dispatcher(Klass::Fs)
	end

	#
	# List of supported commands
	#
	def commands
		{
		}
	end

	#
	# Name for this dispatcher
	#
	def name
		"Standard extension"
	end

end

end
end
end
end
