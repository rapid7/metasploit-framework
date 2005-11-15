require 'rex/ui'

module Rex
module Ui
module Text

begin 
	require 'readline'

	###
	#
	# This class implements standard input using readline against
	# standard input.  It supports tab completion.
	#
	###
	class Input::Readline < Rex::Ui::Text::Input
		include ::Readline

		#
		# Initializes the readline-aware Input instance for text.
		#
		def initialize(tab_complete_proc = nil)
			if (tab_complete_proc)
				::Readline.completion_proc = tab_complete_proc
			end
		end

		#
		# Regular old gets, reads a line of input and returns it to the caller.
		#
		def gets
			self.fd.gets
		end

		#
		# Prompt-based getline using readline.
		#
		def pgets
			if ((line = readline(prompt, true)))
				HISTORY.pop if (line.empty?)
				return line + "\n"
			else
				eof = true
				return line
			end
		end

		#
		# Returns the $stdin handle.
		#
		def fd
			$stdin
		end

		#
		# Indicates that this input medium as a shell builtin, no need 
		# to extend.
		#
		def intrinsic_shell?
			true
		end

		#
		# The prompt that is to be displayed.
		#
		attr_accessor :prompt
		#
		# The output handle to use when displaying the prompt.
		#
		attr_accessor :output

	end
rescue LoadError
end

end
end
end
