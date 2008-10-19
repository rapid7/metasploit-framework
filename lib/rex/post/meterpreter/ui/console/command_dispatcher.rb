require 'rex/logging'

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
	# The hash of file names to class names after a module has already been
	# loaded once on the client side.
	#
	@@file_hash = {}

	#
	# Checks the file name to hash association to see if the module being
	# requested has already been loaded once.
	#
	def self.check_hash(name)
		@@file_hash[name]
	end

	#
	# Sets the file path to class name association for future reference.
	#
	def self.set_hash(name, klass)
		@@file_hash[name] = klass
	end

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