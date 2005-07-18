require 'rex/ui'
require 'rex/post/meterpreter'

module Rex
module Post

###
#
# Console
# -------
#
# This class provides a shell driven interface to the meterpreter client API.
#
###
class Meterpreter::Console

	def initialize
		# Initialize the pseudo-shell
		shell = Rex::Ui::Text::Shell.new("%bmeterpreter%c ")

		# Point the input/output handles elsewhere
		reset_ui
	end

	#
	# Initialize's the shells I/O handles
	#
	def init_ui(input, output)
		shell.init_ui(input, output)
	end

	#
	# Resets the shell's I/O handles
	#
	def reset_ui
		shell.reset_ui
	end

	#
	# Called when someone wants to interact with the meterpreter client.  It's
	# assumed that init_ui has been called prior.
	#
	def interact(&block)
		shell.run { |line, args|

			# 

			# If a block was supplied, call it, otherwise return false
			if (block)
				block.call
			else
				false
			end
		}
	end

end

end
end
