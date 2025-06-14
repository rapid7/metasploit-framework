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
class Flatfile < Rex::Logging::Sinks::Stream

  #
  # Creates a flatfile log sink instance that will be configured to log to
  # the supplied file path.
  #
  def initialize(file)
    super(File.new(file, 'a'))
  end

end

end end end
