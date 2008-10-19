module Msf
module Session
module Provider

###
#
# This interface is to be implemented by a session that is capable of
# providing multiple command shell interfaces simultaneously.  Inherently,
# MultiCommandShell classes must also provide a mechanism by which they can
# implement the SingleCommandShell interface.
#
###
module MultiCommandShell

	include SingleCommandShell

	#
	# Initializes the default command shell as expected from 
	# SingleCommandShell.
	#
	def init_shell()
		raise NotImplementedError
	end

	#
	# Opens a new command shell context and returns the handle.
	#
	def open_shell()
		raise NotImplementedError
	end

	#
	# Reads data from a command shell.  If shell is nil, the default
	# command shell from init_shell is used.
	#
	def read_shell(length = nil, shell = nil)
		raise NotImplementedError
	end

	#
	# Writes data to a command shell.  If shell is nil, the default
	# command shell from init_shell is used.
	#
	def write_shell(buf, shell = nil)
		raise NotImplementedError
	end

	#
	# Closes the provided command shell or the default one if none is
	# given.
	#
	def close_shell(shell = nil)
		raise NotImplementedError
	end

end

end
end
end