module Msf
module Logging
module Sinks

###
#
# Flatfile
# --------
#
# This class implements the LogSink interface and backs it against a 
# file on disk.
#
###
class Flatfile

	include Msf::Logging::LogSink

	def initialize(file)
		self.fd = File.new(file, "a")

		ilog(0, "Logging initialized.")
	end

	def cleanup
		ilog(0, "Logging finished.")

		fd.close
	end

protected

	def log(sev, level, msg, from)
		if (sev == LOG_RAW)
			fd.write(msg)
		else
			fd.write("[#{get_current_timestamp}] (sev=#{sev},level=#{level}): #{msg}\n")
		end
	end

	attr_accessor :fd

end

end; end; end
