require 'rex'
require 'rex/logging/log_sink'

module Rex
module Logging

###
#
# LogDispatcher
# -------------
#
# The log dispatcher associates log sources with log sinks.  A log source
# is a unique identity that is associated with one and only one log sink.
# For instance, the framework-core registers the 'core' 
#
###
class LogDispatcher

	def initialize()
		self.log_sinks        = {}
		self.log_sinks_rwlock = ReadWriteLock.new
	end

	# Returns the sink that is associated with the supplied source
	def [](src)
		sink = nil

		log_sinks_rwlock.synchronize_read {
			sink = log_sinks[src]
		}

		return sink
	end

	# Calls the source association routnie
	def []=(src, sink)
		store(src, sink)
	end

	# Associates the supplied source with the supplied sink
	def store(src, sink)
		log_sinks_rwlock.synchronize_write {
			if (log_sinks[src] == nil)
				log_sinks[src] = sink
			else
				raise(
					RuntimeError, 
					"The supplied log source #{src} is already registered.",
					caller)
			end
		}
	end

	# Removes a source association if one exists
	def delete(src)
		sink = nil

		log_sinks_rwlock.synchronize_write {
			sink = log_sinks[src]
			
			log_sinks.delete(src)
		}

		if (sink)
			sink.cleanup

			return true
		end

		return false
	end

	# Performs the actual log operation against the supplied source
	def log(sev, src, level, msg, from)
		log_sinks_rwlock.synchronize_read {
			if ((sink = log_sinks[src]))
				sink.log(sev, src, level, msg, from)
			end
		}
	end

	attr_accessor :log_sinks, :log_sinks_rwlock
end

end
end

###
#
# An instance of the log dispatcher exists in the global namespace, along
# with stubs for many of the common logging methods.  Various sources can
# register themselves as a log sink such that logs can be directed at
# various targets depending on where they're sourced from.  By doing it
# this way, things like sessions can use the global logging stubs and
# still be directed at the correct log file.
#
###
ExceptionCallStack = "__EXCEPTCALLSTACK__"

def dlog(msg, src = 'core', level = 0, from = caller)
	$dispatcher.log(LOG_DEBUG, src, level, msg, from)
end

def elog(msg, src = 'core', level = 0, from = caller)
	$dispatcher.log(LOG_ERROR, src, level, msg, from)
end

def wlog(msg, src = 'core', level = 0, from = caller)
	$dispatcher.log(LOG_WARN, src, level, msg, from)
end

def ilog(msg, src = 'core', level = 0, from = caller)
	$dispatcher.log(LOG_INFO, src, level, msg, from)
end

def rlog(msg, src = 'core', level = 0, from = caller)
	if (msg == ExceptionCallStack)
		msg = "\nCall stack:\n" + $@.join("\n") + "\n"
	end

	$dispatcher.log(LOG_RAW, src, level, msg, from)
end

def register_log_source(src, sink)
	$dispatcher[src] = sink
end

def deregister_log_source(src)
	$dispatcher.delete(src)
end

# Creates the global log dispatcher
$dispatcher = Rex::Logging::LogDispatcher.new

