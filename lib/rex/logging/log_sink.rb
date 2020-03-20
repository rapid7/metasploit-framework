# -*- coding: binary -*-

module Rex
module Logging

###
#
# This abstract interface is what must be implemented by any class
# that would like to register as a log sink on a given LogDispatcher
# instance, such as the Framework object.
#
###
module LogSink

  def cleanup
  end

  #
  # This method must be implemented by any derived log sink classes and is
  # intended to take the supplied parameters and persist them to an arbitrary
  # medium.
  #
  def log(sev, src, level, msg)
    raise NotImplementedError
  end

protected

  #
  # This method returns the current timestamp in MM/DD/YYYY HH:Mi:SS format.
  #
  def get_current_timestamp
    return Time.now.strftime("%m/%d/%Y %H:%M:%S")
  end

end

end
end

require 'rex/logging/sinks/flatfile'
require 'rex/logging/sinks/stderr'
require 'rex/logging/sinks/timestamp_flatfile'
