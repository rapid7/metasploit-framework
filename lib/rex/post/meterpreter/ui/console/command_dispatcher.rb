module Rex
module Post
module Meterpreter
module Ui

###
#
# Base class for all command dispatchers within the meterpreter console user
# interface.
#
###
module Console::CommandDispatcher

	include Rex::Ui::Text::DispatcherShell::CommandDispatcher

	#
	# Returns the meterpreter client context.
	#
	def client
		shell.client
	end

	#
	# Log that an error occurred.
	#
	def log_error(msg)
		print_error(msg)

		elog(msg, 'meterpreter')

		dlog("Call stack:\n#{$@.join("\n")}", 'meterpreter')
	end

end

end
end
end
end
