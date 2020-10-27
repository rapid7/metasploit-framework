# -*- coding: binary -*-
module Rex
module Logging
module Sinks

###
#
# This class implements the LogSink interface and backs it against stderr
###
class Stderr

  include Rex::Logging::LogSink

  #
  # Writes log data to stderr
  #

  def log(sev, src, level, msg) # :nodoc:
    if (sev == LOG_RAW)
      $stderr.write(msg)
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
      $stderr.write("[#{get_current_timestamp}] [#{code}(#{level})] #{src}: #{msg}\n")
    end

    $stderr.flush
  end

protected

end

end end end
