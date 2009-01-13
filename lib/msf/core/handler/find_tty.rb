require 'msf/core/handler/find_port'

module Msf
module Handler

###
#
# This handler expects a interactive TTY on the supplied socket/io object
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
		if(sock.respond_to?('commandstate'))
			return (sock.commandstate ? false : true)
		end
		return true
	end	  

end

end
end
