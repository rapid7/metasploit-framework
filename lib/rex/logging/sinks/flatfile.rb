module Rex
module Logging
module Sinks

###
#
# This class implements the LogSink interface and backs it against a 
# file on disk.
#
###
class Flatfile

	include Rex::Logging::LogSink

	def initialize(file)
		self.fd = File.new(file, "a")
	end

	def cleanup
		fd.close
	end

	def log(sev, src, level, msg, from)
		if (sev == LOG_RAW)
			fd.write(msg)
		else
			code = 'i'

			case sev
				when LOG_DEBUG
					code = 'd'
				when LOG_ERROR
					code = 'e'
				when LOG_INFO
					code = 'i'
				when LOG_WARN
					code = 'w'
			end
			fd.write("[#{get_current_timestamp}] [#{code}(#{level})] #{src}: #{msg}\n")
		end
			
		fd.flush
	end

protected

	attr_accessor :fd

end

end end end
