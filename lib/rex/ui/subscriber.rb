module Rex
module Ui

###
#
# This module provides a subscriber interface to input/output.
#
###
module Subscriber

	##
	#
	# Output
	# ------
	#
	# Subscribes to the output half of the user interface.
	#
	##
	module Output

		def print_line(msg)
			user_output.print_line(msg) if (user_output)
		end

		def print_status(msg)
			user_output.print_status(msg) if (user_output)
		end

		def print_error(msg)
			user_output.print_error(msg) if (user_output)
		end
		
		def print_good(msg)
			user_output.print_good(msg) if (user_output)
		end

		def print(msg)
			user_output.print(msg) if (user_output)
		end

		def flush
			user_output.flush if (user_output)
		end

		attr_accessor :user_output

	end

	##
	#
	# Input
	# -----
	#
	# Subscribes to the input half of the user interface.
	#
	##
	module Input

		def gets
			user_input.gets if (user_input)
		end
		
		attr_accessor :user_input

	end

	include Output
	include Input

	#
	# Sets the input and output handles.
	#
	def init_ui(input = nil, output = nil)
		self.user_input  = input
		self.user_output = output
	end

	#
	# Disables input/output
	#
	def reset_ui
		self.user_input  = nil
		self.user_output = nil
	end

end

end
end
