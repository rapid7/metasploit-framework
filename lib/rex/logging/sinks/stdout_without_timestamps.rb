# -*- coding: binary -*-


module Rex
module Logging
module Sinks

###
#
# This class implements the LogSink interface and backs it against stdout
###
class StdoutWithoutTimestamps < Rex::Logging::Sinks::Stream

  #
  # Creates a log sink instance that will be configured to log to stdout
  #
  def initialize(*_attrs)
    super($stdout)
  end

  #
  # Writes log data to a stream
  #
  #
  # Writes log data to a stream
  #
  def log(sev, src, level, msg) # :nodoc:
    if sev == LOG_RAW
      stream.write(msg)
    else
      stream.write("[#{log_code_for(sev)}(#{level})] #{src}: #{msg}\n")
    end

    stream.flush
  end

end

end end end
