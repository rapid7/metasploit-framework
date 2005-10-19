module Msf
module Handler

###
#
# Handler
# -------
#
# The 'none' handler, for no connection.
#
###
module None
	include Msf::Handler
	
	#
	# Returns the handler type
	#
	def self.handler_type
		return "none"
	end
	
	def self.general_handler_type
		return "none"
	end

end

end
end
