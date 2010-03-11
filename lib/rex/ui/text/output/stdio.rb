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
		case config[:color]
		when true
			return true
		when false
			return false
		else # auto
			term = Rex::Compat.getenv('TERM')
			return (term and term.match(/(?:vt10[03]|xterm(?:-color)?|linux|screen|rxvt)/i) != nil)
		end
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

