# -*- coding: binary -*-
module Rex
module Logging
module Sinks

###
#
# This class implements the LogSink interface and backs it against a stream
###
class Stream

  include Rex::Logging::LogSink

  def initialize(stream)
    @stream = stream
  end

  #
  # Writes log data to a stream
  #
  def log(sev, src, level, msg) # :nodoc:
    if (sev == LOG_RAW)
      stream.write(msg)
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
      stream.write("[#{get_current_timestamp}] [#{code}(#{level})] #{src}: #{msg}\n")
    end

    stream.flush
  end

protected

  attr_accessor :stream # :nodoc:

end

end end end
