require 'Shared/Constants'

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

	def dlog(level, msg, from = caller)
		log(LOG_DEBUG, level, msg, from)
	end

	def elog(level, msg, from = caller)
		log(LOG_ERROR, level, msg, from)
	end

	def wlog(level, msg, from = caller)
		log(LOG_WARN, level, msg, from)
	end

	def ilog(level, msg, from = caller)
		log(LOG_INFO, level, msg, from)
	end

	def rlog(msg)
		log(LOG_RAW, 0, msg, nil)
	end

protected

	def log(sev, level, msg, from)
		raise NotImplementedError
	end

	def get_current_timestamp
		return Time.now.strftime("%m/%d/%Y %H:%M:%S")
	end

end

end; end

require 'Shared/Logging/Sinks/Flatfile'
