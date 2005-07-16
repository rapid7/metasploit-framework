require 'rex/ui'

module Rex
module Ui
module Text

###
#
# Stdio
# -----
#
# This class implements input against standard in.
#
###
class Input::Stdio < Rex::Ui::Text::Input
	def gets
		return $stdin.gets
	end

	def eof?
		return $stdin.eof?
	end

	def fd
		return $stdin
	end
end

end
end
end
