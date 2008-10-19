module Msf
module Session
module Provider

###
#
# This interface is to be implemented by a session that is only capable of
# providing an interface to a single command shell.
#
###
module SingleCommandShell

	#
	# Initializes the command shell.
	#
	def init_shell()
		raise NotImplementedError
	end

	#
	# Reads data from the command shell.
	#
	def read_shell(length = nil)
		raise NotImplementedError
	end

	#
	# Writes data to the command shell.
	#
	def write_shell(buf)
		raise NotImplementedError
	end

	#
	# Closes the command shell.
	#
	def close_shell()
		raise NotImplementedError
	end

end

end
end
end