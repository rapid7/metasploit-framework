# -*- coding: binary -*-
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

  #
  # Creates a flatfile log sink instance that will be configured to log to
  # the supplied file path.
  #
  def initialize(file)
    self.fd = File.new(file, "a")
  end

  def cleanup # :nodoc:
    fd.close
  end

  def log(sev, src, level, msg, from) # :nodoc:
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

  attr_accessor :fd # :nodoc:

end

end end end
