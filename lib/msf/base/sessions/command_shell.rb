require 'msf/base'

module Msf
module Sessions

###
# 
# CommandShell
# ------------
#
# This class provides basic interaction with a command shell on the remote
# endpoint.  This session is initialized with a stream that will be used
# as the pipe for reading and writing the command shell.
#
###
class CommandShell

	#
	# This interface supports basic interaction.
	#
	include Msf::Session::Basic

	#
	# This interface supports interacting with a single command shell.
	#
	include Msf::Session::Provider::SingleCommandShell

	#
	# The shell will have been initialized by default
	#
	def init_shell
		return true
	end

	#
	# Read from the command shell
	#
	def read_shell(length = nil)
		return rstream.read(length)
	end

	#
	# Writes to the command shell
	#
	def write_shell(buf)
		rstream.write(buf)
	end

	#
	# Closes the shell
	#
	def close_shell()
		rstream.close
	end

end

end
end
