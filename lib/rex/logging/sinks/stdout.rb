# -*- coding: binary -*-
module Rex
module Logging
module Sinks

###
#
# This class implements the LogSink interface and backs it against stdout
###
class Stdout < Rex::Logging::Sinks::Stream

  #
  # Creates a log sink instance that will be configured to log to stdout
  #
  def initialize(*_attrs)
    super($stdout)
  end

end

end end end
