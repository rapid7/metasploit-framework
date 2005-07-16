module Msf
module Session

###
#
# Interactive
# -----------
#
# This class implements the stubs that are needed to provide an interactive
# session.
#
###
module Interactive

	#
	# Returns that, yes, indeed, this session supports going interactive with
	# the user.
	#
	def interactive?
		true
	end

	#
	# Starts interacting with the session.
	#
	def interact
	end

	#
	# The local input handle.  Must inherit from Rex::Ui::Text::Input.
	#
	attr_accessor :linput
	#
	# The local output handle.  Must inherit from Rex::Ui::Output.
	#
	attr_accessor :loutput

end

end
end
