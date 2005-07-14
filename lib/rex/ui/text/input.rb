require 'rex/ui'

module Rex
module Ui
module Text

###
#
# Input
# -----
#
# This class acts as a base for all input mediums.  It defines
# the interface that will be used by anything that wants to 
# interact with a derived class.
#
###
class Input

	require 'rex/ui/text/input/stdio'
	require 'rex/ui/text/input/readline'
	
	def initialize
		self.eof = false
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
