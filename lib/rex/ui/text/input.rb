require 'rex/ui'

module Rex
module Ui
module Text

###
#
# This class acts as a base for all input mediums.  It defines
# the interface that will be used by anything that wants to 
# interact with a derived class.
#
###
class Input

	require 'rex/ui/text/input/stdio'
	require 'rex/ui/text/input/readline'
	require 'rex/ui/text/input/socket'
	
	def initialize
		self.eof = false
	end

	#
	# Whether or not the input medium supports readline.
	#
	def supports_readline
		true
	end
	
	#
	# Stub for tab completion reset
	#
	def reset_tab_completion
	end

	#
	# Calls the underlying system read.
	#
	def sysread(len)
		raise NotImplementedError
	end

	#
	# Gets a line of input
	#
	def gets
		raise NotImplementedError
	end

	#
	# Has the input medium reached end-of-file?
	#
	def eof?
		return eof
	end

	#
	# Returns a pollable file descriptor that is associated with this
	# input medium.
	#
	def fd
		raise NotImplementedError
	end

	#
	# Indicates whether or not this input medium is intrinsicly a
	# shell provider.  This would indicate whether or not it
	# already expects to have a prompt.
	#
	def intrinsic_shell?
		false
	end

	attr_accessor :eof

end

end
end
end
