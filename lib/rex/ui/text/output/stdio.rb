require 'rex/ui'

module Rex
module Ui
module Text

###
#
# Stdio
# -----
#
# This class implements output against standard out.
#
###
class Output::Stdio < Rex::Ui::Text::Output

	def print(msg = '')
		$stdout.print(msg)
		$stdout.flush

		msg
	end
end

end
end
end
