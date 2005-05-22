require 'Msf/Shared/Constants'

module Msf
module Logging

###
#
# LogSink
# -------
#
# This abstract interface is what must be implemented by any class
# that would like to register as a log sink on a given LogDispatcher
# instance, such as the Framework object.
#
###
module LogSink

	def cleanup
	end

	def log(sev, src, level, msg, from)
		raise NotImplementedError
	end

protected

	def get_current_timestamp
		return Time.now.strftime("%m/%d/%Y %H:%M:%S")
	end

end

end; end

require 'Msf/Shared/Logging/Sinks/Flatfile'
