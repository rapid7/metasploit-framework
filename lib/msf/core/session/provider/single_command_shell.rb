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
	def shell_init()
		raise NotImplementedError
	end

	#
	# Reads data from the command shell.
	#
	def shell_read(length = nil)
		raise NotImplementedError
	end

	#
	# Writes data to the command shell.
	#
	def shell_write(buf)
		raise NotImplementedError
	end

	#
	# Closes the command shell.
	#
	def shell_close()
		raise NotImplementedError
	end

end

end
end
end
