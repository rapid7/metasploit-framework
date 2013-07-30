# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Standard API extension.
#
###
class Console::CommandDispatcher::Android

	require 'rex/post/meterpreter/ui/console/command_dispatcher/android/common'


	Klass = Console::CommandDispatcher::Android

	Dispatchers =
		[
			Klass::Common,

		]

	include Console::CommandDispatcher

	def initialize(shell)
		super

		Dispatchers.each { |d|
			shell.enstack_dispatcher(d)
		}
	end

	#
	# List of supported commands.
	#
	def commands
		{
		}
	end

	#
	# Name for this dispatcher
	#
	def name
		"Android Standard extension"
	end

end

end
end
end
end
