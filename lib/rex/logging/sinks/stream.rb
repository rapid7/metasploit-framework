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
    if sev == LOG_RAW
      stream.write(msg)
    else
      stream.write("[#{get_current_timestamp}] [#{log_code_for(sev)}(#{level})] #{src}: #{msg}\n")
    end

    stream.flush
  end

  def cleanup # :nodoc:
    stream.close
  end

  protected

  attr_accessor :stream # :nodoc:

  #
  # This method returns the corresponding log code for the given severity
  #
  def log_code_for(sev)
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

    code
  end

end

end end end
