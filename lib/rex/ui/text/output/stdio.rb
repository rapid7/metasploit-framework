require 'rex/ui'

module Rex
module Ui
module Text

###
#
# This class implements output against standard out.
#
###
class Output::Stdio < Rex::Ui::Text::Output

	def supports_color?
		# Color is disabled until we resolve some bugs
		#return false

		term = Rex::Compat.getenv('TERM')
		(term and term.match(/(?:vt10[03]|xterm(?:-color)?|linux|screen)/i) != nil)
	end

	#
	# Prints the supplied message to standard output.
	#
	def print_raw(msg = '')
		$stdout.print(msg)
		$stdout.flush

		msg
	end
end

end
end
end
