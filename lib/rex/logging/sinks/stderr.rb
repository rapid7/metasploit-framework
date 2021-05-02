# -*- coding: binary -*-
module Rex
module Logging
module Sinks

###
#
# This class implements the LogSink interface and backs it against stderr
###
class Stderr < Rex::Logging::Sinks::Stream

  #
  # Creates a log sink instance that will be configured to log to stderr
  #
  def initialize(*_attrs)
    super($stderr)
  end

end

end end end
