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

	#
	# Prints the supplied message to standard output.
	#
	def print(msg = '')
		$stdout.print(msg)
		$stdout.flush

		msg
	end
end

end
end
end