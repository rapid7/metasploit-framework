require 'msf/core/handler/find_port'

module Msf
module Handler

###
#
# This handler expects a plain Unix command shell on the supplied socket
#
###
module FindTty

	include FindPort

	#
	# Returns the string representation of the handler type, in this case
	# 'find_tag'.
	#
	def self.handler_type
		return "find_shell"
	end

	#
	# Returns the connection oriented general handler type, in this case
	# 'find'.
	#
	def self.general_handler_type
		"find"
	end

	#
	# Remove the CPORT option from our included FindPort class
	#
	def initialize(info = {})
		super
		options.remove_option('CPORT')
	end

protected

	def _check_shell(sock)
		return true
	end	  

end

end
end
