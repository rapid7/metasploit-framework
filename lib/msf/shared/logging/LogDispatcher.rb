require 'Shared'

module Msf
module Logging

###
#
# LogDispatcher
# -------------
#
# This interface is included in the Framework class and is used to provide a
# common interface for dispatching logs to zero or more registered log sinks.
# Log sinks are typically backed against arbitrary storage mediums, such as a
# flatfile, a database, or the console.  The log dispatcher itself is really
# just a log sink that backs itself against zero or more log sinks rather than
# a file, database, or other persistent storage.
#
###
module LogDispatcher

	include Msf::Logging::LogSink

	def initialize()
		initialize_log_dispatcher
	end

	#
	# Log sink registration
	#
	
	def add_log_sink(sink)
		log_sinks_rwlock.synchronize_write {
			log_sinks << sink
		}
	end

	def remove_log_sink(sink)
		log_sinks_rwlock.synchronize_write {
			sink.cleanup

			log_sinks.delete(sink)
		}
	end

	#
	# Log dispatching
	#
protected

	def initialize_log_dispatcher
		self.log_sinks        = []
		self.log_sinks_rwlock = ReadWriteLock.new
	end

	def log(sev, level, msg, from)
		log_sinks_rwlock.synchronize_read {
			log_sinks.each { |sink|
				sink.dispatch_log(sev, level, msg, from)
			}
		}
	end

	attr_accessor :log_sinks
	attr_accessor :log_sinks_rwlock

end

end; end
